import { log } from './logger';

const debug = true;

export function inotifyHooks() {
  if (debug) {
    log(` [*] hooking inotify methods`);
  }

  inotifyInitHook();
  inotifyAddHook();
  inotifyRmHook();

  if (debug) {
    log(` [+] finished hooking inotify methods`);
  }
}

function inotifyInitHook() {
  const inotify_initPtr = Module.findExportByName(null, 'inotify_init');
  if (inotify_initPtr) {
    if (debug) {
      log(` [+] inotify : inotify_init hooked @ ${inotify_initPtr}`);
    }

    Interceptor.attach(inotify_initPtr, {
      onLeave: function (retval) {
        log(` [!] inotify_init : fd : ${retval}`);
      },
    });
  }
}

// from https://cs.android.com/android/kernel/superproject/+/common-android-mainline:common/include/uapi/linux/inotify.h;l=31
enum INOTIFY_FLAGS {
  IN_ACCESS = 0x00000001 /* File was accessed */,
  IN_MODIFY = 0x00000002 /* File was modified */,
  IN_ATTRIB = 0x00000004 /* Metadata changed */,
  IN_CLOSE_WRITE = 0x00000008 /* Writtable file was closed */,
  IN_CLOSE_NOWRITE = 0x00000010 /* Unwrittable file closed */,
  IN_OPEN = 0x00000020 /* File was opened */,
  IN_MOVED_FROM = 0x00000040 /* File was moved from X */,
  IN_MOVED_TO = 0x00000080 /* File was moved to Y */,
  IN_CREATE = 0x00000100 /* Subfile was created */,
  IN_DELETE = 0x00000200 /* Subfile was deleted */,
  IN_DELETE_SELF = 0x00000400 /* Self was deleted */,
  IN_MOVE_SELF = 0x00000800 /* Self was moved */,

  /* the following are legal events.  they are sent as needed to any watch */
  IN_UNMOUNT = 0x00002000 /* Backing fs was unmounted */,
  IN_Q_OVERFLOW = 0x00004000 /* Event queued overflowed */,
  IN_IGNORED = 0x00008000 /* File was ignored */,

  /* helper events */
  IN_CLOSE = IN_CLOSE_WRITE | IN_CLOSE_NOWRITE /* close */,
  IN_MOVE = IN_MOVED_FROM | IN_MOVED_TO /* moves */,

  /* special flags */
  IN_ONLYDIR = 0x01000000 /* only watch the path if it is a directory */,
  IN_DONT_FOLLOW = 0x02000000 /* don't follow a sym link */,
  IN_EXCL_UNLINK = 0x04000000 /* exclude events on unlinked objects */,
  IN_MASK_CREATE = 0x10000000 /* only create watches */,
  IN_MASK_ADD = 0x20000000 /* add to the mask of an already existing watch */,
  IN_ISDIR = 0x40000000 /* event occurred against dir */,
  IN_ONESHOT = 0x80000000 /* only send event once */,
}

function parseFlags(flags: number) {
  let ret = '';
  const strings = Object.keys(INOTIFY_FLAGS);
  const values = Object.values(INOTIFY_FLAGS);

  values.forEach((value, index) => {
    if ((flags & Number(value)) !== 0) {
      if (ret.length > 0) {
        ret = ret.concat(' | ');
      }
      ret = ret.concat(strings[index]);
    }
  });

  if (ret === '') {
    return 'null';
  }

  return ret;
}

function inotifyAddHook() {
  const inotify_add_watchPtr = Module.findExportByName(null, 'inotify_add_watch');
  if (inotify_add_watchPtr) {
    if (debug) {
      log(` [+] inotify : inotify_add_watch hooked @ ${inotify_add_watchPtr}`);
    }

    Interceptor.attach(inotify_add_watchPtr, {
      onEnter: function (args) {
        const inotify_fd = args[0];
        const path = args[1].readUtf8String();
        const flags = args[2].toUInt32();
        log(` [+] inotify_add_watch(${inotify_fd}, ${path}, ${parseFlags(flags)})`);
      },
    });
  }
}

function inotifyRmHook() {
  const inotify_rm_watchPtr = Module.findExportByName(null, 'inotify_rm_watch');
  if (inotify_rm_watchPtr) {
    if (debug) {
      log(` [+] inotify : inotify_rm_watch hooked @ ${inotify_rm_watchPtr}`);
    }

    Interceptor.attach(inotify_rm_watchPtr, {
      onEnter: function (args) {
        const inotify_fd = args[0];
        const path = args[1].readUtf8String();
        const flags = args[2].toUInt32();
        log(` [-] inotify_rm_watch(${inotify_fd}, ${path}, ${parseFlags(flags)})`);
      },
    });
  }
}
