#!/usr/bin/env bash

echo "Build target rust"
cargo b --release --package millegrilles_landing --bin millegrilles_landing
