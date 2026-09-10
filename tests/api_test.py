#!/usr/bin/env python3
from utils.colors import colors, puts, sep
from utils.firegexapi import FiregexAPI
import argparse
import secrets

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--address",
        "-a",
        type=str,
        required=False,
        help="Address of firegex backend",
        default="http://127.0.0.1:4444/",
    )
    parser.add_argument(
        "--password", "-p", type=str, required=True, help="Firegex password"
    )
    args = parser.parse_args()
    sep()
    puts("Testing will start on ", color=colors.cyan, end="")
    puts(f"{args.address}", color=colors.yellow)

    firegex = FiregexAPI(args.address)

    # Connect to Firegex
    # Half of what follows is about passwords, and an instance started with
    # `--unsafe-disable-auth` answers 403 to every one of those endpoints by design. Say
    # so and stop, rather than reporting a password that would not change as a failure:
    # the rest of the suite runs against such an instance perfectly well, this one alone
    # needs authentication to be on.
    if firegex.status().get("auth_disabled"):
        puts("This instance has authentication turned off, and this suite is mostly "
             "about authentication. Start one with a password to run it.", color=colors.yellow)
        exit(1)

    if firegex.status()["status"] == "init":
        if firegex.set_password(args.password):
            puts(f"Sucessfully set password to {args.password} ✔", color=colors.green)
        else:
            puts(
                "Test Failed: Unknown response or password already put ✗",
                color=colors.red,
            )
            exit(1)
    else:
        if firegex.login(args.password):
            puts("Sucessfully logged in ✔", color=colors.green)
        else:
            puts("Test Failed: Unknown response or wrong passowrd ✗", color=colors.red)
            exit(1)

    if firegex.status()["loggined"]:
        puts("Correctly received status ✔", color=colors.green)
    else:
        puts("Test Failed: Unknown response or not logged in✗", color=colors.red)
        exit(1)

    # Prepare second instance
    firegex2 = FiregexAPI(args.address)
    if firegex2.login(args.password):
        puts("Sucessfully logged in on second instance ✔", color=colors.green)
    else:
        puts(
            "Test Failed: Unknown response or wrong passowrd on second instance ✗",
            color=colors.red,
        )
        exit(1)

    if firegex2.status()["loggined"]:
        puts("Correctly received status on second instance✔", color=colors.green)
    else:
        puts(
            "Test Failed: Unknown response or not logged in on second instance✗",
            color=colors.red,
        )
        exit(1)

    # Change password
    new_password = secrets.token_hex(10)
    if firegex.change_password(new_password, expire=True):
        puts(f"Sucessfully changed password to {new_password} ✔", color=colors.green)
    else:
        puts("Test Failed: Coundl't change the password ✗", color=colors.red)
        exit(1)

    # Check if we are still logged in
    if firegex.status()["loggined"]:
        puts("Correctly received status after password change ✔", color=colors.green)
    else:
        puts(
            "Test Failed: Unknown response or not logged after password change ✗",
            color=colors.red,
        )
        exit(1)

    # Check if second session expired and relog

    if not firegex2.status()["loggined"]:
        puts("Second instance was expired currectly ✔", color=colors.green)
    else:
        puts(
            "Test Failed: Still logged in on second instance, expire expected ✗",
            color=colors.red,
        )
        exit(1)
    if firegex2.login(new_password):
        puts("Sucessfully logged in on second instance ✔", color=colors.green)
    else:
        puts(
            "Test Failed: Unknown response or wrong passowrd on second instance ✗",
            color=colors.red,
        )
        exit(1)

    # Change it back
    if firegex.change_password(args.password, expire=False):
        puts("Sucessfully restored the password ✔", color=colors.green)
    else:
        puts("Test Failed: Coundl't change the password ✗", color=colors.red)
        exit(1)

    # Check if we are still logged in
    if firegex2.status()["loggined"]:
        puts("Correctly received status after password change ✔", color=colors.green)
    else:
        puts(
            "Test Failed: Unknown response or not logged after password change ✗",
            color=colors.red,
        )
        exit(1)

    # Backups never contain the password/secret (see export_db), so importing one back
    # must not lock the current session out or force a re-login.
    backup = firegex.export_backup()
    if backup:
        puts("Sucessfully exported backup ✔", color=colors.green)
    else:
        puts("Test Failed: Couldn't export backup ✗", color=colors.red)
        exit(1)

    if firegex.import_backup(backup):
        puts("Sucessfully imported backup ✔", color=colors.green)
    else:
        puts("Test Failed: Couldn't import backup ✗", color=colors.red)
        exit(1)

    firegex3 = FiregexAPI(args.address)
    if firegex3.login(args.password):
        puts("Password survived the backup import ✔", color=colors.green)
    else:
        puts("Test Failed: Password was lost/changed after backup import ✗", color=colors.red)
        exit(1)

    # Whether firegex asks for a password at all is a property of where it is deployed,
    # not of the configuration in a backup. It has to survive an import for the same
    # reason the password does — and it did not, once: the key lives in `keys_values`, so
    # it rode along in the dump, and the restart at the end of the import re-seeded it
    # from the container's environment, reverting a `run.py config` made hours earlier.
    #
    # Turned off around the import on purpose. Asserting it is still on afterwards would
    # pass either way on a container whose environment says the same thing; the bug only
    # shows where the running state and the boot-time environment disagree, which is what
    # a runtime change is.
    if not firegex.set_auth_mode(True):
        puts("Test Failed: could not turn authentication off ✗", color=colors.red)
        exit(1)
    if not firegex.import_backup(firegex.export_backup()):
        puts("Test Failed: could not import a backup with authentication off ✗", color=colors.red)
        exit(1)
    if firegex.status()["auth_disabled"] is True:
        puts("Authentication mode survived the backup import ✔", color=colors.green)
    else:
        puts("Test Failed: the backup import turned authentication back on ✗", color=colors.red)
        exit(1)
    # Back on, with the session signed before it went off — everything below expects it.
    if not firegex.set_auth_mode(False) or firegex.status()["auth_disabled"] is not False:
        puts("Test Failed: could not turn authentication back on ✗", color=colors.red)
        exit(1)
    puts("And it goes back on afterwards ✔", color=colors.green)

    # --- authentication is a runtime setting, not a boot-time one ----------------
    # It used to be read from the environment once, at startup, which meant a password
    # handed to a running instance was stored and never asked for while `run.py config`
    # reported "it will take effect immediately".
    sep()
    puts("Authentication at runtime", color=colors.white, is_bold=True)

    def check(name, ok, extra=""):
        if ok:
            puts(f"  [+] {name}", color=colors.green)
        else:
            puts(f"  [-] {name} {extra}", color=colors.red)
            exit(1)

    check("it starts on", firegex.status()["auth_disabled"] is False)

    anonymous = FiregexAPI(args.address)
    check("and an anonymous caller is refused",
          anonymous.status()["loggined"] is False)

    check("an administrator can turn it off", firegex.set_auth_mode(True))
    check("the status says so at once", firegex.status()["auth_disabled"] is True)
    check("and the same anonymous caller is now let in",
          anonymous.status()["loggined"] is True and isinstance(anonymous.get_interfaces(), list))

    # Nothing new is signed while it is off, so a token is proof of having been an
    # administrator before it was — which is what re-enabling asks for.
    why = anonymous.set_auth_mode_error(False)
    check("a caller who arrived afterwards cannot put it back",
          why is not None and "before it was turned off" in why, str(why))
    check("but the session that turned it off can",
          firegex.set_auth_mode(False))
    check("and it is asked for again",
          firegex.status()["auth_disabled"] is False and anonymous.status()["loggined"] is False)
    check("while the password still works",
          FiregexAPI(args.address).login(args.password))

    puts("List of available interfaces:", color=colors.yellow)
    for interface in firegex.get_interfaces():
        puts(
            "name: {}, address: {}".format(interface["name"], interface["addr"]),
            color=colors.yellow,
        )
