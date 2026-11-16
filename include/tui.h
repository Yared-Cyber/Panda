#ifndef tui_h
#define tui_h

enum {
	tui_quit = 0;
	tui_ping = 1;
	tui_portscan = 2;
	tui_both = 3;
};

void tui_logo(void);

int tui_menu(const char* host);

void tui_section(const char* title);

void tui_progress(int done, int total, int n_open);

void tui_progress_done(void);

#endif;
