#!/bin/bash

pylint_test_result="$(python3 -m pylint --errors-only ./Tests | grep demisto_sdk)"

echo Pylint exit code on Test directory: $pylint_test_result

if [ -n "$pylint_test_result" ] ; then
    echo Pylint exit code on Test directory: $pylint_test_result
    exit 1
fi
#pylint_utils_result="$(python3 -m pylint --errors-only ./Utils | grep -c demisto_sdk | cat)"