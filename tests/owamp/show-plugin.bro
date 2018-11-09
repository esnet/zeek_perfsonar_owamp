# @TEST-EXEC: bro -NN PerfSONAR::OWAMP |sed -e 's/version.*)/version)/g'  >output
# @TEST-EXEC: btest-diff output
