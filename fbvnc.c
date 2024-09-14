/*
 * FBVNC: a small Linux framebuffer VNC viewer
 *
 * Copyright (C) 2009-2021 Ali Gholami Rudi
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/input.h>
#include <rfb/rfbclient.h>
#include "draw.h"
#include "vnc.h"


#define MIN(a, b)	((a) < (b) ? (a) : (b))
#define MAX(a, b)	((a) > (b) ? (a) : (b))
#define OUT(msg)	write(1, (msg), strlen(msg))

#define VNC_PORT	"5900"
#define SCRSCRL		2
#define MAXRES		(1 << 16)

static int cols, rows;		/* framebuffer dimensions */
static int bpp;			/* bytes per pixel */
static int srv_cols, srv_rows;	/* server screen dimensions */
static int or, oc;		/* visible screen offset */
static int mr, mc;		/* mouse position */
static int nodraw;		/* do not draw anything */
static int nodraw_ref;		/* pending screen redraw */
static long vnc_nr;		/* number of bytes received */
static long vnc_nw;		/* number of bytes sent */

static char buf[MAXRES];

static rfbCredential* get_credential(rfbClient* cl, int credentialType){
	rfbCredential *c = malloc(sizeof(rfbCredential));
	if (!c) {
		return NULL;
	}
	c->userCredential.username = malloc(RFB_BUF_SIZE);
	if (!c->userCredential.username) {
		free(c);
		return NULL;
	}
	c->userCredential.password = malloc(RFB_BUF_SIZE);
	if (!c->userCredential.password) {
		free(c->userCredential.username);
		free(c);
		return NULL;
	}

	if(credentialType != rfbCredentialTypeUser) {
	    rfbClientErr("something else than username and password required for authentication\n");
	    return NULL;
	}

	rfbClientLog("username and password required for authentication!\n");
	printf("user: ");
	fgets(c->userCredential.username, RFB_BUF_SIZE, stdin);
	printf("pass: ");
	fgets(c->userCredential.password, RFB_BUF_SIZE, stdin);

	/* remove trailing newlines */
	c->userCredential.username[strcspn(c->userCredential.username, "\n")] = 0;
	c->userCredential.password[strcspn(c->userCredential.password, "\n")] = 0;

	return c;
}

static int vnc_init(rfbClient *cl)
{
	srv_cols = cl->width;
	srv_rows = cl->height;

	/* set up the framebuffer */
	if (fb_init(getenv("FBDEV")))
		return -1;
	cols = MIN(srv_cols, fb_cols());
	rows = MIN(srv_rows, fb_rows());
	bpp = FBM_BPP(fb_mode());
	mr = rows / 2;
	mc = cols / 2;


	// cl->format.redMax=255;
	// cl->format.greenMax=255;
	// cl->format.blueMax=255;

	// rfbPixelFormat format = cl->format;
    // printf("Bits per pixel: %d\n", format.bitsPerPixel);
    // printf("Depth: %d\n", format.depth);
    // printf("Big Endian: %s\n", format.bigEndian ? "Yes" : "No");
    // printf("True Colour: %s\n", format.trueColour ? "Yes" : "No");
    // printf("Red max: %d, shift: %d\n", format.redMax, format.redShift);
    // printf("Green max: %d, shift: %d\n", format.greenMax, format.greenShift);
    // printf("Blue max: %d, shift: %d\n", format.blueMax, format.blueShift);

	return 0;
}

// TODO: modify using rfbSendFramebufferUpdateRequest
// do I need to refresh the fb?
// static int vnc_refresh(int fd, int inc)
// {
// 	struct vnc_updaterequest fbup_req;
// 	fbup_req.type = VNC_UPDATEREQUEST;
// 	fbup_req.inc = inc;
// 	fbup_req.x = htons(oc);
// 	fbup_req.y = htons(or);
// 	fbup_req.w = htons(cols);
// 	fbup_req.h = htons(rows);
// 	return vwrite(fd, &fbup_req, sizeof(fbup_req)) < 0 ? -1 : 0;
// }

static inline void fb_set(int r, int c, void *mem, int len)
{
	//memcpy(fb_mem(r) + c * bpp, mem, len * bpp);
	int i,j;
	for(i=0;i<len;i++){
		//memcpy(fb_mem(r) + (c + i)*bpp, mem + i*bpp, 4);
		for(j=0;j<4;j++){
			*(char*)(fb_mem(r) + (c + i)*bpp + j) = *(char*)(mem + i*bpp + j);
		}
	}
}

// x, y, w, h are server framebuffer coordinates
// Assume server framebuffer can be larger than client framebuffer
static void drawfb(unsigned char *s, int x, int y, int w, int h)
{
	int sc, sr;		/* starting column, row in client fb */
	int er, ec;		/* ending column, row in client fb, non-inclusive */
	int i;

	// the region being updated does not intersect with current visible region
	if(x+w < oc || x > oc+cols || y+h < or || y > or+rows) return;

	sr = MAX(0, y - or);
	sc = MAX(0, x - oc);
	er = MIN(or + rows, y+h-or);
	ec = MIN(oc + cols, x+w-oc);

	for (i = sr; i < er; i++)
		fb_set(i, sc, s + ((i + or) * srv_cols + sc + oc) * bpp, ec - sc);
}

static inline void update(rfbClient* cl,int x,int y,int w,int h) {
	//printf("called update %d %d %d %d\n", x, y, w, h);
	drawfb(cl->frameBuffer, x, y, w, h);
	// int i,j;
	// for(i=0;i<rows;i++){
	// 	for(j=0;j<cols;j++){
	// 		char* from = cl->frameBuffer + i * srv_
	// 	}
	// }
}

//TODO: modify mouse handler using SendPointerEvent
static int rat_event(rfbClient *cl, int ratfd)
{
	char ie[4] = {0};
	int mask = 0;
	int or_ = or, oc_ = oc;
	if (ratfd > 0 && read(ratfd, &ie, sizeof(ie)) != 4)
		return -1;
	/* ignore mouse movements when nodraw */
	if (nodraw)
		return 0;
	mc += ie[1];
	mr -= ie[2];

	if (mc < oc)
		oc = MAX(0, oc - cols / SCRSCRL);
	if (mc >= oc + cols && oc + cols < srv_cols)
		oc = MIN(srv_cols - cols, oc + cols / SCRSCRL);
	if (mr < or)
		or = MAX(0, or - rows / SCRSCRL);
	if (mr >= or + rows && or + rows < srv_rows)
		or = MIN(srv_rows - rows, or + rows / SCRSCRL);
	mc = MAX(oc, MIN(oc + cols - 1, mc));
	mr = MAX(or, MIN(or + rows - 1, mr));
	if (ie[0] & 0x01)
		mask |= rfbButton1Mask;
	if (ie[0] & 0x04)
		mask |= rfbButton2Mask;
	if (ie[0] & 0x02)
		mask |= rfbButton3Mask;
	if (ie[3] > 0)		/* wheel up */
		mask |= rfbButton4Mask;
	if (ie[3] < 0)		/* wheel down */
		mask |= rfbButton5Mask;

	SendPointerEvent(cl, mc, mr, mask);
	// if visible region changed, need a full refresh
	if (or != or_ || oc != oc_)
		SendFramebufferUpdateRequest(cl, oc, or, cols, rows, FALSE);
	return 0;
}

static void showmsg(void)
{
	char msg[128];
	sprintf(msg, "\x1b[HFBVNC \t\t nr=%-8ld\tnw=%-8ld\r", vnc_nr, vnc_nw);
	OUT(msg);
}

static void nodraw_set(int val)
{
	if (val && !nodraw)
		showmsg();
	if (!val && nodraw)
		nodraw_ref = 1;
	nodraw = val;
}

//TODO: modify keyboard handler using SendKeyEvent
static int kbd_event(rfbClient *cl, int kbdfd)
{
	char key[1024];
	int i, nr;

	if ((nr = read(kbdfd, key, sizeof(key))) <= 0 )
		return -1;
	for (i = 0; i < nr; i++) {
		int k = -1;
		int mod[4];
		int nmod = 0;
		switch (key[i]) {
		case 0x08:
		case 0x7f:
			k = 0xff08;
			break;
		case 0x09:
			k = 0xff09;
			break;
		case 0x1b:
			if (i + 2 < nr && key[i + 1] == '[') {
				if (key[i + 2] == 'A')
					k = 0xff52;
				if (key[i + 2] == 'B')
					k = 0xff54;
				if (key[i + 2] == 'C')
					k = 0xff53;
				if (key[i + 2] == 'D')
					k = 0xff51;
				if (key[i + 2] == 'H')
					k = 0xff50;
				if (k > 0) {
					i += 2;
					break;
				}
			}
			k = 0xff1b;
			if (i + 1 < nr) {
				mod[nmod++] = 0xffe9;
				k = key[++i];
				if (k == 0x03)	/* esc-^C: quit */
					return -1;
			}
			break;
		case 0x0d:
			k = 0xff0d;
			break;
		case 0x0:	/* c-space: stop/start drawing */
			nodraw_set(1 - nodraw);
		default:
			k = (unsigned char) key[i];
		}
		if ((k >= 'A' && k <= 'Z') || strchr(":\"<>?{}|+_()*&^%$#@!~", k))
			mod[nmod++] = 0xffe1;
		if (k >= 1 && k <= 26) {
			k = 'a' + k - 1;
			mod[nmod++] = 0xffe3;
		}
		if (k > 0) {
			int j;
			for (j = 0; j < nmod; j++)
				SendKeyEvent(cl, mod[j], 1);
				
			SendKeyEvent(cl, k, 1);
			SendKeyEvent(cl, k, 0);
			for (j = 0; j < nmod; j++)
				SendKeyEvent(cl, mod[j], 0);
		}
	}
	return 0;
}

static void term_setup(struct termios *ti)
{
	struct termios termios;
	OUT("\033[2J");		/* clear the screen */
	OUT("\033[?25l");	/* hide the cursor */
	showmsg();
	tcgetattr(0, &termios);
	*ti = termios;
	cfmakeraw(&termios);
	tcsetattr(0, TCSANOW, &termios);
}

static void term_cleanup(struct termios *ti)
{
	tcsetattr(0, TCSANOW, ti);
	OUT("\r\n\033[?25h");	/* show the cursor */
}

//TODO
static void mainloop(rfbClient *cl, int kbd_fd, int rat_fd)
{
	struct pollfd ufds[3];
	int err;
	ufds[0].fd = kbd_fd;
	ufds[0].events = POLLIN;
	ufds[1].fd = rat_fd;
	ufds[1].events = POLLIN;
	ufds[2].fd = cl->sock;
	ufds[2].events = POLLIN;
	//rat_event(vnc_fd, -1); // what does this do
	while (1) {
		err = poll(ufds, 3, 500);
		if (err == -1 && errno != EINTR)
			break;
		if (err){
			if (ufds[0].revents & POLLIN)
				if (kbd_event(cl, kbd_fd) == -1)
					break;
			if (ufds[1].revents & POLLIN)
				if (rat_event(cl, rat_fd) == -1)
					break;
			if (ufds[2].revents & POLLIN){
				if(WaitForMessage(cl, 0) < 0){
					rfbClientCleanup(cl);
					break;
				}
				if(!HandleRFBServerMessage(cl))
				{
					rfbClientCleanup(cl);
					break;
				}
				// printf("called HandleRFBServerMessage\n");
				// I want to only keep track of the current part of the screen,
				// But libvncclient automatically requests the full framebuffer
				// SendFramebufferUpdateRequest(cl, 0, 0, cols, rows, TRUE);
			}
		}
	}
}

static void signalreceived(int sig)
{
	if (sig == SIGUSR1 && !nodraw)		/* disable drawing */
		nodraw_set(1);
	if (sig == SIGUSR2 && nodraw)		/* enable drawing */
		nodraw_set(0);
}

int main(int argc, char * argv[])
{
	struct termios ti;
	int rat_fd;
	rfbClient* cl;

	// initialize rfbClient
	/* 16-bit: cl=rfbGetClient(5,3,2); */
	cl=rfbGetClient(8,3,4);

	cl->GotFrameBufferUpdate=update;
	cl->GetCredential = get_credential;
    cl->format.redShift=16;
	cl->format.greenShift=8;
	cl->format.blueShift=0;

	if(!rfbInitClient(cl,&argc,argv))
	{
		cl = NULL; /* rfbInitClient has already freed the client struct */
		printf("failed to initialize vnc client\n");
		rfbClientCleanup(cl);
		return -1;
	}

	if(vnc_init(cl) < 0){
		return -1;
	}

	// only keep track of part of the screen
	SendFramebufferUpdateRequest(cl, 0, 0, cols, rows, TRUE);

	if (getenv("TERM_PGID") != NULL && atoi(getenv("TERM_PGID")) == getppid())
		if (tcsetpgrp(0, getppid()) == 0)
			setpgid(0, getppid());
	term_setup(&ti);

	/* entering intellimouse for using mouse wheel */
	rat_fd = open("/dev/input/mice", O_RDWR);
	write(rat_fd, "\xf3\xc8\xf3\x64\xf3\x50", 6);
	read(rat_fd, buf, 1);
	signal(SIGUSR1, signalreceived);
	signal(SIGUSR2, signalreceived);
	mainloop(cl, 0, rat_fd);

	term_cleanup(&ti);
	fb_free();
	close(rat_fd);
	return 0;
}
