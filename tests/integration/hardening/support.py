from tests.integration.support import rule_for

F401 = rule_for("F401")


def canary_script(marker) -> str:
    return f'#!/bin/sh\ntouch "{marker}"\n'
