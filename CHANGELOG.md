## v1.18

* bug fix: use format flags - logPrintf() not logPrint()
* bug fix: parseObjectIdentifier() now returns []byte{0} rather than error
  when it receive zero length input
* use gomock
* start using go modules
* start a changelog
