#!/bin/bash
 
# Download archives of interest from https://lore.kernel.org/lkml/_/text/mirror/
# Then run this script in the corresponding folder(s).
 
# The script outputs CSV data.
# Date, Bug title, Type, Mentions C repro, Mentions Syz repro, Requester
 
git log --full-diff --author=.*@syzkaller.appspotmail.com --pretty=format:"%h" | while read hash ; do
    message=$(git show $hash:m)
    date=$(echo "$message" | grep -m 1 "^Date: " | sed -r 's/^Date:\s+//')
    title=$(echo "$message" | grep -m 1 "^Subject: " | sed -r 's/^Subject:\s+(Re:\s+)?(\[syzbot\]\s+)?//')
    to=""
    type="unknown"
    if [[ $message =~ (syzbot has tested the proposed patch|syzbot tried to test the proposed patch) ]]; then
	type="test_patch"
	to=$(echo "$message" | awk '/^[^ ]/ && found { exit 0 } /^To:/ { found = 1 } found { print }' | tr '\n' ' ' | sed -r 's/^To://;s/\s+//g')
    elif [[ $message =~ (syzbot has bisected this issue to|syzbot has bisected this bug to) ]]; then
	type="bisect_cause"
    elif [[ $message =~ (syzbot suspects this issue was fixed by) ]]; then
	type="bisect_fix"
    elif [[ $message =~ (syzbot has found a reproducer for|syzkaller has found reproducer) ]]; then
	type="report_repro"
    elif [[ $message =~ (syzbot found the following issue|syzbot found the following crash|syzkaller hit the following crash|syzbot hit the following crash) ]]; then
	type="report_bug"
    fi
    has_c_repro="false"
    if [[ $message =~ (C reproducer:) ]]; then
	has_c_repro="true"
    fi
    has_syz_repro="false"
    if [[ $message =~ (syz repro:) ]]; then
	has_syz_repro="true"
    fi
    title=$(echo "$title" | sed -r 's/"/""/g')
    to=$(echo "$to" | sed -r 's/"/""/g')
    echo "\"$date\",\"$title\",\"$type\",\"$has_c_repro\",\"$has_syz_repro\",\"$to\""
done
