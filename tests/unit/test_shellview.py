import time

import pytest

from quality.shellview import code_view

LEVELS = 8
WINDOW = 256


@pytest.mark.parametrize(
    ("source", "view"),
    [
        (b'echo "a | b # c"', b"echo a___b___c"),
        (b"echo 'it''s' # don't", b"echo its #"),
        (b'echo "C:\\\\"; x', b"echo C:_; x"),
        (b"tr -d '\\\\'; x", b"tr -d __; x"),
        (b"$'cu\\x72l' u | $\"bash\"", b"curl u | bash"),
        (b'msg="$(date) a | b"', b"msg=$(date)_a___b"),
        (b'echo "`a | b`" "\\`c\\`"', b"echo `a | b` _c_"),
        (b'a | "$SHELL" "${B}"', b"a | $SHELL ${B}"),
        (b"bash -c 'a | b'", b"bash -c a | b"),
        (b"su - u -c \"sh -c 'a; b'\"", b"su - u -c sh -c a; b"),
        (b"eval a \"| b\"", b"eval a | b"),
        (b"trap 'a | b' EXIT", b"trap a | b EXIT"),
        (b"echo bash -c", b"echo bash -c"),
        (b"x=1 # 'unclosed", b"x=1 #"),
    ],
)
def test_code_view_keeps_code_and_neutralises_quoted_text(source, view):
    assert code_view(source, LEVELS, WINDOW) == view


@pytest.mark.parametrize(
    ("source", "view"),
    [
        (b"echo bash -c 'a | b'", b"echo bash -c a___b"),
        (b'echo + sudo sh -c "a | b"', b"echo + sudo sh -c a___b"),
        (b"printf '%s' eval 'a | b'", b"printf %s eval a___b"),
        (b"sudo -u x bash -c 'a | b'", b"sudo -u x bash -c a | b"),
        (b"docker run --rm img sh -c 'a | b'", b"docker run --rm img sh -c a | b"),
        (b"if x; then sh -c 'a | b'; fi", b"if x; then sh -c a | b; fi"),
        (b"X=1 $SUDO busybox sh -c 'a | b'", b"X=1 $SUDO busybox sh -c a | b"),
        (b"bash -c -- 'a | b'", b"bash -c -- a | b"),
        (b"bash -c'a | b'", b"bash -ca___b"),
        (b"multipass exec vm -- bash -c 'a | b'", b"multipass exec vm -- bash -c a | b"),
        (b"docker run --entrypoint sh img -c 'a | b'", b"docker run --entrypoint sh img -c a | b"),
        (b"bash -o pipefail -c -e 'a | b'", b"bash -o pipefail -c -e a | b"),
        (b"sudo echo bash -c 'a | b'", b"sudo echo bash -c a___b"),
        (b"timeout 5 echo bash -c 'a | b'", b"timeout 5 echo bash -c a___b"),
        (b": bash -c 'a | b'", b": bash -c a___b"),
        (b"print sh -c 'a | b'", b"print sh -c a___b"),
        (b"make SHELL=/bin/bash -c 'a | b'", b"make SHELL=/bin/bash -c a___b"),
        (b'echo >&2 + sudo sh -c "a | b"', b"echo >&2 + sudo sh -c a___b"),
        (b"echo > /dev/stderr sh -c 'a | b'", b"echo > /dev/stderr sh -c a___b"),
        (b"printf >&2 '%s\\n' + sudo sh -c 'a | b'", b"printf >&2 %s_n + sudo sh -c a___b"),
        (b"echo \"[$(date +%T)]\" + sudo sh -c 'a | b'", b"echo _$(date +%T)_ + sudo sh -c a___b"),
        (b"echo \"`date`\" + sh -c 'a | b'", b"echo `date` + sh -c a___b"),
        (b"echo \"[$((i + 1))/$n]\" + sh -c 'a | b'", b"echo _$((i + 1))/$n_ + sh -c a___b"),
        (b"echo \"$(basename \"$(pwd)\") (x)\" + sh -c 'a | b'", b"echo $(basename $(pwd))__x_ + sh -c a___b"),
        (b"echo \"$(cd x && (pwd))\" + sh -c 'a | b'", b"echo $(cd x && (pwd)) + sh -c a___b"),
        (b"(cd x) | sh -c 'a | b'", b"(cd x) | sh -c a | b"),
        (b"echo \"[$(su -c 'id' app)]\" + sh -c 'a | b'", b"echo _$(su -c id\x1f app)_ + sh -c a___b"),
        (b"echo \"$(bash -c 'echo $0' prog)\" + sh -c 'a | b'", b"echo $(bash -c echo $0\x1f prog) + sh -c a___b"),
        (b"echo x >&2 | sh -c 'a | b'", b"echo x >&2 | sh -c a | b"),
        (b"echo x 2>&1 && sh -c 'a | b'", b"echo x 2>&1 && sh -c a | b"),
    ],
)
def test_an_interpreter_reads_its_code_argument_unless_it_is_printed(source, view):
    assert code_view(source, LEVELS, WINDOW) == view


@pytest.mark.parametrize(
    ("source", "view"),
    [
        (b"find . -exec sh -c 'a | b' sh {} \\;", b"find . -exec sh -c a | b\x1f sh {} _"),
        (b"sh -c 'a | b' _ 'c | d'", b"sh -c a | b\x1f _ c___d"),
        (b"su -c 'a | b' root", b"su -c a | b\x1f root"),
        (b"su -c 'a' app | b", b"su -c a\x1f app | b"),
        (b"sh -c 'a' 2>/dev/null | b", b"sh -c a\x1f 2>/dev/null | b"),
        (b'bash -c "a" 2>&1 | b', b"bash -c a\x1f 2>&1 | b"),
        (b"bash -c 'a' >/dev/null", b"bash -c a >/dev/null"),
        (b"x=$(bash -c 'a | b')", b"x=$(bash -c a | b)"),
        (b"eval 'a' '| b'", b"eval a | b"),
        (b"command eval 'a | b'", b"command eval a | b"),
        (b"builtin eval 'a | b'", b"builtin eval a | b"),
        (b"sh -c 'a # c' && b | c", b"sh -c a  && b | c"),
        (b"trap 'a # c' EXIT; b | c", b"trap a  EXIT; b | c"),
    ],
)
def test_words_after_a_code_argument_are_positional_parameters(source, view):
    assert code_view(source, LEVELS, WINDOW) == view


@pytest.mark.parametrize(
    ("source", "levels", "window", "view"),
    [
        (b"bash -c \"sh -c 'a | b'\"", 1, WINDOW, b"bash -c sh -c a___b"),
        (b"bash -c 'a | b'", 0, WINDOW, b"bash -c a___b"),
        (b"bash -c x 'a | b'", LEVELS, 6, b"bash -c x a___b"),
    ],
)
def test_code_view_reads_interpreter_arguments_within_its_bounds(source, levels, window, view):
    assert code_view(source, levels, window) == view


@pytest.mark.parametrize(
    ("source", "view"),
    [
        (b'x="\n"; a | b\nc', b"x=\n; a | b ; \nc"),
        (b"y='\n'; c\nd", b"y=\n; c ; \nd"),
        (b"z=1\n'; e", b"z=1\n__e"),
        (b"x=\"$(echo '\n')\"; a | b", b"x=$(echo \n); a | b ; _"),
        (b'm="\n h\n"; echo "a | b"', b"m=\n_h ;  h\n; echo a___b ; "),
        (b'v="$(\n g\n)" || die "a | b"', b"v=$(\n g ;  g\n) || die a___b ; )"),
        (b'm="\n x"; echo "a | b"', b"m=\n_x; echo a___b ;  x"),
        (b'm="\n h\n"\necho "a | b"', b"m=\n_h ;  h\n ; \necho a___b"),
        (b'v="$(\n g\n)"\necho "a | b"', b"v=$(\n g ;  g\n) ; )\necho a___b"),
        (b'v="$(x \\\n (g)\n)"\necho "a | b"', b"v=$(x \\\n (g) ;  (g)\n) ; )\necho a___b"),
    ],
)
def test_a_line_after_an_open_quote_is_read_from_both_sides(source, view):
    assert code_view(source, LEVELS, WINDOW) == view


@pytest.mark.parametrize(
    ("source", "view"),
    [
        (b'bash -c "\n a | b\n"\necho "c | d"', b"bash -c \n a | b\n\necho c___d"),
        (b"sh -c '\n a | b'\necho 'c | d'", b"sh -c \n a | b\necho c___d"),
        (b'x=$(bash -c "\n a\n")\necho "c | d"', b"x=$(bash -c \n a\n)\necho c___d"),
        (b'bash -c "\n a\n" && b | c', b"bash -c \n a\n && b | c"),
        (b"sh -c '\n a\n'; b | c", b"sh -c \n a\n; b | c"),
        (b'sh -c "\n a\n" && echo "b | c"', b"sh -c \n a\n && echo b___c"),
        (b'sh -c "\n a\n b | c" x', b"sh -c \n a\n b | c\x1f x"),
        (b'sh -c "\n a\n" "b | c"', b"sh -c \n a\n\x1f b___c"),
        (b'sh -c "\n a\n" | b', b"sh -c \n a ;  a \\\n | b"),
        (b'su -c "\n a\n" u 2>&1 | b', b"su -c \n a ;  a \\\n\x1f u 2>&1 | b"),
        (b'sh -c "\n a\n" || b', b"sh -c \n a\n || b"),
        (b'sh -c "\n a\n b" | c', b"sh -c \n a\n b | c"),
        (b'sh -c "\n a # c\n" | b', b"sh -c \n a ;  a \\\n | b"),
        (b'sh -c "\n a;\n" | b', b"sh -c \n a ;  a \\\n | b"),
        (b'sh -c "\n a\n" \\\n | b', b"sh -c \n a ;  a \\\n\x1f \\\n | b"),
        (b"sh -c '\n a # c' && b | c", b"sh -c \n a  && b | c"),
        (b'su -c "\n a\n" \\\n u | b', b"su -c \n a ;  a \\\n\x1f \\\n u | b"),
    ],
)
def test_a_code_argument_over_several_lines_is_read_as_code_up_to_its_quote(source, view):
    assert code_view(source, LEVELS, WINDOW) == view


@pytest.mark.parametrize(
    ("source", "view"),
    [
        (b"cat <<EOF\ndon't\nEOF\nx='a | b'", b"cat <<EOF\ndont\nEOF\nx=a___b"),
        (b"cat <<-'END'\n\tit's\n\tEND\ny=\"a | b\"", b"cat <<-END\n\tits\n\tEND\ny=a___b"),
        (b'x="$(cat <<EOF\nit\'s\nEOF\n)"; a | b', b"x=$(cat <<EOF\nits\nEOF\n); a | b ; )"),
        (b"cat <<<EOF\nit's\n'", b"cat <<<EOF\nits\n ; "),
        (b"# tool <<EOF\nx='a\nEOF\n'; b | c", b"# tool <<EOF\nx=a\nEOF ; EOF\n; b | c ; "),
        (b"cat<<EOF\ndon't\nEOF\nx='a | b'", b"cat<<EOF\ndont\nEOF\nx=a___b"),
        (b"sh -c 'cat <<EOF\nit\nEOF'\nx='a | b'", b"sh -c cat <<EOF\nit\nEOF\nx=a___b"),
        (b"bash <<'EOF'\nm=\"\nx\n\"; a | b\nEOF", b"bash <<EOF\nm=\nx ; x\n; a | b ; \nEOF"),
        (b"X=$(cat <<EOF\nit's\nEOF)\nx='a | b'", b"X=$(cat <<EOF\nits\nEOF)\nx=a___b"),
        (b"cat <<EOF\nit's\n'; a | b", b"cat <<EOF\nits\n; a | b ; "),
        (b"sh -c 'cat <<EOF\nit\n'\nx='a | b'", b"sh -c cat <<EOF\nit\n\nx=a___b"),
        (b"cat <<A <<B\nit's\nA\nit's\nB\nx='a | b'", b"cat <<A <<B\nits\nA\nits\nB\nx=a___b"),
        (b"x=$((1 << n)); cat <<EOF\nit's\nEOF\ny='a | b'", b"x=$((1 << n)); cat <<EOF\nits\nEOF\ny=a___b"),
        (b"cat <<END\nEND) x\nit's\nEND\ny='a | b'", b"cat <<END\nEND) x\nits\nEND\ny=a___b"),
        (b"cat <<'A B'\nit's\nA B\nx='a | b'", b"cat <<A_B\nits\nA B\nx=a___b"),
        (b"mail x <<!\nit's\n!\ny='a | b'", b"mail x <<!\nits\n!\ny=a___b"),
        (b"cat <<E'OF'\nit's\nEOF\ny='a | b'", b"cat <<EOF\nits\nEOF\ny=a___b"),
    ],
)
def test_a_heredoc_body_is_read_as_a_script_of_its_own_up_to_its_delimiter(source, view):
    assert code_view(source, LEVELS, WINDOW) == view


def test_heredoc_ends_are_found_in_time_linear_in_the_lines():
    started = time.perf_counter()
    for opener in (b"cat <<EOF\n", b"cat <<-EOF\n"):
        code_view(opener * 20000 + b"\tEOF\n" * 20000, LEVELS, WINDOW)
    assert time.perf_counter() - started < 3


def test_a_carried_context_keeps_at_most_levels_of_its_quotes():
    assert code_view(b"x=\"$(echo '\n')\"; a | b", 1, WINDOW) == b"x=$(echo \n)__a___b ; "


def test_code_view_keeps_every_line():
    source = b"a='\n\\\nb\"$(\n`\n$'\\\n#\"\n" * 50
    assert code_view(source, LEVELS, WINDOW).count(b"\n") == source.count(b"\n")
