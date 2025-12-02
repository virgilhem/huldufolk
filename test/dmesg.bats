load helpers

@test "outputting to dmesg works" {
    if [ "$(id -u)" != "0" ]; then
        skip "not root, can't test dmesg"
    fi

    : "${UMH_BIN:=${ROOT_DIR}/target/debug/usermode-helper}"

    # don't use our helper: we want to test the dmesg logging bits, and our
    # helper turns off dmesg logging.
    run bash -c "exec -a /bin/true \"$UMH_BIN\""
    echo "$output"
    [ "$status" -eq 1 ]

    dmesg | tail | grep "couldn't read config file ./usermode-helper.conf"
}
