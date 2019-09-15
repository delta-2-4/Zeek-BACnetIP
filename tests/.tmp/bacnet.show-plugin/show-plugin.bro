# @TEST-EXEC: bro -NN Heller::bacnet |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
