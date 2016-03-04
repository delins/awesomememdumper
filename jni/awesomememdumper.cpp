#include <sstream>
#include <fstream>
#include <iostream>
#include <string>
#include <errno.h>
#include <algorithm>
#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdio.h>
#include <cstdlib>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include "classes.h"


int main(int argc, char* argv[]) {
	std::ifstream is;
	std::ofstream os;

	int pid;
	std::string outputDir;
	MemType type;

	std::stringstream ss;
	ss << "Usage: " 
	   << argv[0] 
	   << " PID OUTPUT_DIR {heap|stack|vdso|vvar|vsyscal|file|anon|empty|all|suball}";
	std::string usageMessage(ss.str());
	ss.str("");
	ss.clear();

	// Look for "--help" or "-h"
	if (argc == 2) {
		if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
			std::cout << usageMessage << std::endl;
			return(0);
		}
	}

	// Fail if we get anything other than 3 parameters
	if (argc != 4) {
		std::cerr << usageMessage << std::endl;
		return(1);
	}

	// Parse argument 1: PID
	if (!(pid = std::strtol(argv[1], nullptr, 10))) {
		std::cerr << "Parameter 1 is not a valid PID (" << argv[1] << ")" << std::endl;
		return(1);
	}

	// Parse argument 2: OUTPUT_DIR
	outputDir = argv[2];

	// Parse argument 3: type
	try {
		type = MemTypeConvert::stom(argv[3]);
	} catch (parse_exception &e) {
		std::cerr << "Error: not a valid type (" << argv[3] << ")\n"
				  << usageMessage << std::endl;
		return(1);
	}

	// Done parsing. State what we're trying to do.
	std::cout << "Called as: " << argv[0] << " "
			  				   << pid << " "
			  				   << MemTypeConvert::mtos(type)
			  				   << std::endl;
			  				  
	// Attach to process
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
		perror("PTRACE_ATTACH");
		return(1);
	}

	MapsParser mapsParser(pid);
	int n = mapsParser.parse();
	std::vector<std::shared_ptr<MapEntry>> memVec = mapsParser.retrieveMapEntries(type);
	mapsParser.dumpModifiedMapsFile(outputDir);
	std::cout << "Type of entry to be read: " << MemTypeConvert::mtos(type) << std::endl;	
	std::cout << "Amount of entries to be read: " << memVec.size() << std::endl;
	
	MemReader memReader(pid, std::string(outputDir));

	memReader.readMem(memVec);

	// Detach from process
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		perror("PTRACE_DETACH");
		return(1);
	}
}