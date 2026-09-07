check()
{
	local tool=$1; shift

	local out

	out=$(command -v "$tool" >/dev/null 2>&1 || [ -x "$tool" ])
	check_err $? "$out"

	log_test "$tool"
}

check_pkgconfig()
{
	local tool=$1; shift

	local out

	out=$(pkg-config --exists "$tool" 2>/dev/stdout)
	check_err $? "$out"

	log_test "$tool"
}

ignore_failure()
{
	EXIT_STATUS="$EXIT_STATUS" "$@"
}

echo "Build deps:"
print_divider -

for t in ${DEPS_BUILD_TOOLS}; do
	check "$t"
done

for l in ${DEPS_BUILD_LIBS}; do
	check_pkgconfig "$l"
done

echo

echo "Test deps:"
print_divider -

for t in ${DEPS_TEST_TOOLS}; do
	ignore_failure check "$t"
done

echo

echo "FRR test deps:"
print_divider -

for t in ${DEPS_TEST_FRR}; do
	ignore_failure check "$t"
done

echo

echo "COVERAGE=1 deps:"
print_divider -

for t in ${DEPS_COV_TOOLS}; do
	ignore_failure check "$t"
done

echo

print_divider =

RET=$EXIT_STATUS
log_test "Dependency check"
exit "$EXIT_STATUS"
