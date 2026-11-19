#pragma once
// Build-time embedded assets, pulled straight into flash by the assembler via
// .incbin — no xxd-style C arrays, no LittleFS upload, no multi-KB string
// literals in main.cpp.
//
// IMPORT_BIN(sect, file, sym)  defines  sym      (raw bytes)  + sym_size
// IMPORT_STR(sect, file, sym)  defines  sym      (NUL-terminated bytes)

#define IMPORT_BIN(sect, file, sym) asm (\
    ".section " #sect "\n"                  /* Change section */\
    ".global " #sym "\n"                    /* Export the object address */\
    ".balign 4\n"                           /* Word alignment */\
    #sym ":\n"                              /* Define the object label */\
    ".incbin \"" file "\"\n"                /* Import the file */\
    ".global " #sym "_size\n"               /* Export the object size */\
    ".balign 8\n"                           /* Word alignment */\
    #sym "_size:\n"                         /* Define the object size label */\
    ".long " #sym "_size - " #sym "\n"      /* Define the object size */\
    ".section \".text\"\n")                 /* Restore section */

#define IMPORT_STR(sect, file, sym) asm (\
    ".section " #sect "\n"                  /* Change section */\
    ".balign 4\n"                           /* Word alignment */\
    ".global " #sym "\n"                    /* Export the object address */\
    #sym ":\n"                              /* Define the object label */\
    ".incbin \"" file "\"\n"                /* Import the file */\
    ".byte 0\n"                             /* Null-terminate the string */\
    ".balign 4\n"                           /* Word alignment */\
    ".section \".text\"\n")                 /* Restore section */

#define IMPORT_FLASH_BIN(file, sym) IMPORT_BIN(.rodata, file, sym)
#define IMPORT_FLASH_STR(file, sym) IMPORT_STR(.rodata, file, sym)

#define IMPORT_BIN_DECL(sym) extern const uint8_t sym[]; extern const size_t sym_size;
#define IMPORT_STR_DECL(sym) extern const char sym[];

// ---- dashboard + captive portal (served by web.send_P) ----
IMPORT_FLASH_STR("res/dashboard.html", DASHBOARD_HTML);
IMPORT_FLASH_STR("res/portal.html", PORTAL_HTML);
IMPORT_STR_DECL(DASHBOARD_HTML);
IMPORT_STR_DECL(PORTAL_HTML);

// ---- images: same pattern, ready for the next step ----
// Binary assets keep their size, so a handler can send them with an explicit
// length: web.send(200, "image/png", (const char*)LOGO_PNG, LOGO_PNG_size).
//
// IMPORT_FLASH_BIN("res/logo.png", LOGO_PNG);
// IMPORT_BIN_DECL(LOGO_PNG);
