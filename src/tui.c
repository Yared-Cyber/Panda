#include "tui.h"

#include <stdio.h>
#include <unistd.h>

#define C_RESET  "\033[0m"
#define C_BOLD   "\033[1m"
#define C_DIM    "\033[2m"
#define C_RED    "\033[31m"
#define C_GREEN  "\033[32m"
#define C_YELLOW "\033[33m"
#define C_CYAN   "\033[36m"
 
#define BOX_WIDTH 44
#define BAR_WIDTH 30
 
static const char* const SKULL[] = {
    "              ______",
    "           .-\"      \"-.",
    "          /            \\",
    "         |              |",
    "         |,  .-.  .-.  ,|",
    "         | )(__/  \\__)( |",
    "         |/     /\\     \\|",
    "         (_     ^^     _)",
    "          \\__|IIIIII|__/",
    "           | \\IIIIII/ |",
    "           \\          /",
    "            `--------`"
};


#define SKULL_LINES ((int)(sizeof(SKULL) / sizeof(SKULL[0])))

static int is_tty(void){
	return isatty(STDOUT_FILENO);
}

static void box_edge(void){
	printf("  " C_CYAN "+");
	for (int i = 0; i < BOX_WIDTH; i++)
		putchar('-');
	printf("+" C_RESET "\n");
}



void tui_logo(void){
	if (is_tty())
		printf("\033[2J\033[H");

	printf("\n");

	for (int i = 0; i < SKULL_LINES; i++)
		printf("	" C_RED "%s" C_RESET "\n", SKULL[i]);

	printf("\n");

	box_edge();

	printf("  " C_CYAN "|" C_RESET C_BOLD "%-*s" C_RESET C_CYAN "|" C_RESET "\n", BOX_WIDTH,
			" P A N D A    S C A N N E R");
	printf("  "C_CYAN "|" C_RESET "%-*s" C_CYAN "|" C_RESET "\n", BOX_WIDTH, "  ping / tcp port scan");

	box_edge();

	printf("\n " C_YELLOW "Only scan hosts you own or have permission to test. This tool was built of class assignment and is not for public use." C_RESET "\n\n");
}


int tui_menu(const char* host){
	char line[64];
	int choice;

	printf("  " C_BOLD "Target:" C_RESET " %s\n\n", host);


	for(;;){
		printf("  " C_GREEN "[1]" C_RESET " Ping only\n");
		printf("  " C_GREEN "[2]" C_RESET " Port scan only\n");
		printf("  " C_GREEN "[3]" C_RESET " Ping, then port scan\n");
		printf("  " C_RED   "[0]" C_RESET " Exit\n\n");
		printf("  " C_CYAN "scanner>" C_RESET " ");
		fflush(stdout);

		if (!fgets(line, sizeof(line), stdin))
			return TUI_QUIT;

		if (sscanf(line, "%d", &choice) == 1 && choice >= TUI_QUIT && choice <= TUI_BOTH)
			return choice;

		printf("\n  " C_RED "Invalid choice, try again." C_RESET "\n\n");
	}
}






void tui_section(const char* title){
	printf("\n" C_CYAN "[+]" C_RESET " " C_BOLD "%s" C_RESET "\n\n", title);
}





void tui_progress(int done, int total, int n_open){
	static const char spin[] = "|/-\\";
	static unsigned tick = 0;

	if (!is_tty() || total <= 0) return;

	if (done > total) done = total;

	int filled = done * BAR_WIDTH / total;
	int pct = done * 100 / total;
	char icon = (done >= total) ? '+' : spin[tick++ % 4];


	printf("\r  " C_CYAN "%c" C_RESET " [" C_GREEN, icon);

	for (int i = 0; i < BAR_WIDTH; i++){
		if (i == filled) printf (C_RESET C_DIM);

		putchar( i < filled ? '#' : '-');
	}

	printf(C_RESET "] %3d%%  %d/%d ports  " C_GREEN "%d open" C_RESET "\033[K", pct, done, total, n_open);
	fflush(stdout);
}






void tui_progress_done(void){
	if (is_tty()) printf("\n\n");
	fflush(stdout);
}


