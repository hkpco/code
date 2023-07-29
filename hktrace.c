/*
	hktrace.c

	author   /  hkpco (Chanam Park)
	e-mail   /  chanam.park@hkpco.kr
	homepage /  http://hkpco.kr
	date     /  2006

	no read permission binary copy program
*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/msg.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/ptrace.h>

#if __linux__
#define OFFSET	9
#define OFFSIZ	8
#define MAP	"maps"
#define PTX	long
#define DIFF_T	void *

#elif __FreeBSD__
#define OFFSET	10
#define OFFSIZ	9
#define MAP	"map"
#define PTX	int
#define DIFF_T	caddr_t
#define PTRACE_TRACEME 	PT_TRACE_ME
#define PTRACE_PEEKTEXT	PT_READ_I
#define PTRACE_PEEKDATA	PT_READ_D
#define PTRACE_KILL 	PT_KILL

#else
#error / This system do not support.
#endif

#define VADR 0x08048000
#define KEY  7310
#define PAGE 0x1000

#define _LS   "/bin/ls"
#define _FILE "/usr/bin/file"

int get_virtualaddr( char *pmaps , char *line1 , char *line2 ); // get memory mapping size
int hkt_notice( FILE *flag ); // hktrace information
int chk_x( char *name ); // execute permission check
int hkinfo( char *rname ); // target binary information print
int system_info( void ); // system information print

int main( int argc , char **argv )
{
	int i, fd, cnt1 , cnt2, ptx_sz, chk;
	int childp, fdx, gcp, status;
	struct stat file_info;
	PTX dump, d_buf[PAGE/sizeof(PTX)]={0x00,};

	unsigned int size1, size2;
	char sz1[16]={0x00,}, sz2[16]={0x00,};
	char maps[128]={0x00,};
	char fname[256]={0x00,}, frname[256]={0x00,}, *fnp;
	mode_t check_f;

	if( argc < 2 )
	{
		hkt_notice(stderr);
		fprintf( stderr , "\tUsage -> %s [target_binary]\n\n" , argv[0] );
		return -1;
	}

	/* file state check - begin */
	if( (stat( argv[1] , &file_info ) == -1) )
	{
		fprintf( stderr , "stat error(cause: %s)\n" , argv[1] );
		return -1;
	} check_f = file_info.st_mode;
	if( S_ISDIR(check_f) )
	{
		fprintf( stderr , "error: %s is directory\n" , argv[1] );
		return -1;
	}
	if( access( argv[1] , X_OK ) )
	{
		fprintf( stderr , "error: %s is no excute permission\n" , argv[1] );
		return -1;
	}
	if( (chk_x(argv[1])) && (S_ISLNK(check_f)) )
	{
		fprintf( stderr , "error: %s is not able to execute\n" , argv[1] );
		return -1;
	}
	/* file state check - end */

	hkt_notice(stdout);
	printf( "\t[+] target name -  %s\n" , argv[1] );
	printf( "\t[+] information -  " );
	hkinfo(argv[1]);
	system_info();

	childp = fork();
	if( childp == 0 )
	{
		if( (fdx =  open( "/dev/null" , O_WRONLY )) < 0 )
		{
			perror( "child proccess open() error" );
			return -1;
		}
		dup2( fdx , 0 );
		dup2( fdx , 1 );
		dup2( fdx , 2 );
		// ignore(child process's file descriptor)

		ptrace( PTRACE_TRACEME , 0 , 0 , 0 ); // tracebit set
		execl( argv[1] , argv[1] , NULL ); // child process's memory -> target binary overwrite

		return 0;
	}

	wait(&status);
	if( WIFSIGNALED(status) )
	{
		fprintf( stderr , "child proccess %d was abnormal exit.\n" , gcp );
		return -1;
	}
	// child process stand by

	gcp = childp;
	snprintf( maps , sizeof(maps) , "/proc/%d/%s" , gcp , MAP );
	// mapping file name save

	ptx_sz = sizeof(PTX);
	if( (chk = get_virtualaddr( maps , sz1 , sz2 )) == 0 )
	{
		sscanf( sz1 , "%x" , &size1 );
		sscanf( sz2 , "%x" , &size2 );
		cnt1 = cnt2 = 0;
	} // get memory mapping size
	else
	{
		printf( "\t[>] size notice -  used file size instead of memory mapping size\n" );
		size1 = size2 =  (int)VADR + (int)file_info.st_size;
		cnt1 = cnt2 = 0;
	} // if can not access mapping file, get file size

	strncpy( fname , argv[1] , sizeof(fname) -1 );
	if( (fnp = strrchr( fname , '/' )) != 0 )
		fnp = fnp +1;
	else
		fnp = fname;
	// target_name get

	snprintf( frname , sizeof(frname) -1 , "%s.hk" , fnp );
	if( (fd = open( frname , O_WRONLY | O_CREAT | O_TRUNC , 0700 )) < 0 )
	{
		perror( "open" );
		return -1;
	}
	if( (chmod( frname , 0700 )) < 0 )
	{
		perror( "chmod" );
		return -1;
	}

	/* text segment dump routine */
	for( i = 0 ; i < size1 - VADR ; i+=ptx_sz , cnt1++ )
	{
		dump = ptrace( PTRACE_PEEKTEXT , gcp , (DIFF_T)(VADR +i) , 0 );
		d_buf[cnt1] = dump;

		if( cnt1 == PAGE/ptx_sz -1 )
		{
			write( fd , &d_buf , sizeof(d_buf) );
			memset( d_buf , 0x0 , sizeof(d_buf) );
			cnt1 = -1;
		}
	}
	if( chk ) write( fd , &d_buf , (size1 % PAGE) );
	printf( "\n\t[+] %p-%p copy ok.\n" , (int *)VADR , (int *)size1 );

	/* data segment dump routine */
	for( i = 0 ; i < size2 - size1 ; i+=ptx_sz , cnt2++ )
	{
		dump = ptrace( PTRACE_PEEKDATA , gcp , (DIFF_T)(size1 +i) , 0 );
		d_buf[cnt2] = dump;

		if( cnt2 == PAGE/ptx_sz -1 )
		{
			write( fd , &d_buf , sizeof(d_buf) );
			memset( d_buf , 0x0 , sizeof(d_buf) );
			cnt2 = -1;
		}
	}
	if( !chk )
		printf( "\t[+] %p-%p copy ok.\n" , (int *)size1 , (int *)size2 );

	ptrace( PTRACE_KILL , gcp , 0 , 0 );
	// tracing process kill

	printf("\n");
	printf( "\t!! [%s] created.\n" , frname );
	printf( "\t!! [%s] " , frname );
	hkinfo(frname);
	printf("\n");

	close(fd);
	return 0;
}

int get_virtualaddr( char *pmaps , char *line1 , char *line2 )
{
	FILE *fp;
	char buffer[256]={0x00,};
	char *bp = buffer;
	struct stat maps_info;

	if( access( pmaps , R_OK ) )
		return 1;

	if( (fp = fopen( pmaps , "r" )) == NULL )
		return 1;

	if( (stat( pmaps , &maps_info )) == -1 )
		return 1;

	if( maps_info.st_size == 0 )
		return 1;

	while( fgets( buffer , sizeof(buffer) , fp ) )
	{
		if( ( strstr( bp , "08048000" ) ) == NULL )
		{
			memset( buffer , 0x0 , sizeof(buffer) );
			continue;
		}
		else
		{
			memcpy( line1 , bp +OFFSET , OFFSIZ );
			memset( buffer , 0x0 , sizeof(buffer) );
			break;
		}
	}

	fgets( buffer , sizeof(buffer) , fp );
	memcpy( line2 , bp +OFFSET , OFFSIZ );

	fclose(fp);
	return 0;
}


int hkt_notice( FILE *flag )
{
	fprintf( flag ,
		"\n\t==================== hktrace ====================\n"
		"\thktrace is no-read permission binary copying tool\n"
		"\ttarget program is needed execute-permission only\n"
		"\tavailable system is Linux and FreeBSD\n"
		"\tcreate filename is *.hk\n\n"
		"\tmade by hkpco (Chanam Park)\n"
		"\tchanam.park@hkpco.kr , http://hkpco.kr/\n"
		"\t=================================================\n\n"
	       );

	return 0;
}

int chk_x( char *name )
{
	FILE *fp;
	char buffer[512] = {0x00,};
	char fn[512] = {0x00,};

	snprintf( fn , sizeof(fn) -1 , "%s %s" , _FILE , name );
	if( (fp = popen( fn , "r" )) == NULL )
	{
		perror( "popen(chk_x())" );
		return -1;
	}

	fgets( buffer , sizeof(buffer) -1 , fp );
	pclose(fp);

	if( strstr( buffer , "executable" ) == NULL )
		return 1;

	else
		return 0;
}

int hkinfo( char *rname )
{
	FILE *pn;
	char buff[512] = {0x00,};

	snprintf( buff , sizeof(buff) -1 , "%s -al %s\n" , _LS , rname );
	if( (pn = popen( buff , "r" )) == NULL )
	{
		perror( "popen(hkinfo())" );
		return -1;
	}

	memset( buff , 0x0 , sizeof(buff) );
	fgets( buff , sizeof(buff) -1 , pn );
	pclose(pn);

	printf( "%s" , buff );
	return 0;
}

int system_info( void )
{
	struct utsname name;

	if( uname(&name) < 0 )
	{
		perror( "uname" );
		return -1;
	}

	printf( "\t[+] system info -  %s %s\n" , name.sysname , name.release );
	return 0;
}
