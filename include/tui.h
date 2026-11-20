#ifndef TUI_H
#define TUI_H

enum {
	TUI_QUIT     = 0,
	TUI_PING     = 1,
	TUI_PORTSCAN = 2,
	TUI_BOTH     = 3};

void tui_logo(void);

int tui_menu(const char* host);

void tui_section(const char* title);

void tui_progress(int done, int total, int n_open);

void tui_progress_done(void);

#endif
