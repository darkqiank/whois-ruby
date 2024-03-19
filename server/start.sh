#!/bin/bash
ps -ef | grep "unicorn" | grep -v grep | awk '{print $2}' | xargs kill -9
bundle exec unicorn -c unicorn_config.rb -l 0.0.0.0:4567
# bundle exec unicorn -D -l 0.0.0.0:4567