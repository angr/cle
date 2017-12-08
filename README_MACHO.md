# Mach-O Support Notes and Caveats

The Mach-O support provided by this contribution is considered experimental but stable. 
It has been mainly tested with ARM64 Mach-O binaries and a few ARMv7 binaries. 

As of 14.12.2016 the system can be used to load both Mach-O executables as well as libraries. 
However some caveats apply: 


## CAVEATS

* Currently this system can load only ONE binary, i.e. loading a binary with all its dependencies is not possible.
* No rebasing support
 * Mach-O rebasing requires involvement of the entire binary in order to interpret a linker script embedded in said binary. 
  * Currently the interface for binaries an CLE does not provide the required capabilities (turn `rebase_addr` into a property?)
* Not all fields are filled in accordance with Angr's expectations.
 * Overall integration into Angr/CLE could be better 
* PAGEZERO is not mapped to conserve memory
