#include <regex>
#include <fstream>
#include <sstream>
#include <iostream>
#include <string>
#include "classes.h"
#include <array>
#include <memory>
#include <exception>
#include <sys/wait.h>
#include <stdio.h>
#include <fcntl.h>    /* For O_RDWR */
#include <unistd.h>   /* For open(), creat() */
#include <map>
#include <iomanip>

MapsParser::MapsParser(int pid) : pid{pid} {
	std::stringstream ss;
	ss << "/proc/" << pid << "/maps";
	maps_file = ss.str();
}

int MapsParser::parse() {
	std::ifstream is(maps_file);
	if (!is.is_open()) {
		// What to do?
	}

	// Initialize empty vectors for the keys
	memMap[MemType::_HEAP] = {};
	memMap[MemType::_STACK] = {};
	memMap[MemType::_VDSO] = {};
	memMap[MemType::_VVAR] = {};
	memMap[MemType::_VSYSCALL] = {};
	memMap[MemType::_FILE] = {};
	memMap[MemType::_ANON] = {};
	memMap[MemType::_EMPTY] = {};
	memMap[MemType::_ALL] = {};
	memMap[MemType::_SUBALL] = {};

	std::vector<std::array<unsigned long, 2>> v;
	int lineNo = 0;
	for (std::string s; std::getline(is, s); ) {
		mapEntryStrings.push_back(s);
		try {
			MapEntry mapEntry(lineNo, s);
			memMap[mapEntry.memType()].push_back(std::make_shared<MapEntry>(mapEntry));
			memMap[MemType::_ALL].push_back(std::make_shared<MapEntry>(mapEntry));
			if (mapEntry.memType() != MemType::_FILE) {
				memMap[MemType::_SUBALL].push_back(std::make_shared<MapEntry>(mapEntry));
			}
		} catch (parse_exception &e) {
			std::cerr << "Error parsing entry (" << s << "): " << e.what() << std::endl;
		}
		++lineNo;
	}	
	return memMap[MemType::_ALL].size();
}

void MapsParser::dumpModifiedMapsFile(const std::string &dir) {
	std::string outputPath;
	if (dir.compare(dir.size(), 1, "/") == 0) {
		outputPath = dir + "modded_maps";
	} else {
		outputPath = dir + "/modded_maps";
	}
	std::ofstream os(outputPath, std::ios::trunc);
	std::vector<std::shared_ptr<MapEntry>> vec = memMap[MemType::_ALL];
	for (auto i = vec.begin(); i != vec.end(); ++i) {
		os << (*i)->modifiedMapsFormat() << std::endl;
	}
}

std::vector<std::shared_ptr<MapEntry>> MapsParser::retrieveMapEntries(MemType type) {
	return memMap[type];
}


MemReader::MemReader(int pid, const std::string &dir) 
	: pid{pid} {
	if (dir.compare(dir.size()-1, 1, "/") != 0) {
		outputDir = dir + "/";
	} else {
		outputDir = dir;
	}
	std::stringstream ss;
	ss << "/proc/" << pid << "/mem";
	memFile = ss.str();
}

unsigned long MemReader::readMem(std::vector<std::shared_ptr<MapEntry>> &entries) {
	int memFd;
	unsigned long totalBytesWritten = 0;
	waitpid(pid, NULL, 0);

	if ((memFd = open(memFile.c_str(), O_RDWR)) < 0) {
		perror("OPEN_MEM_FILE");
		return(1);	
	}

	for (auto i = entries.begin(); i < entries.end(); i++) {

		totalBytesWritten += readMemSingle((**i), memFd);
	}
	return totalBytesWritten;
}

unsigned long MemReader::readMemSingle(MapEntry &entry, int memFd) {
	unsigned long startAddress = entry.getStartAddress();
	unsigned long endAddress = entry.getEndAddress();
	std::stringstream ss;
	ss << outputDir // ends with a slash, taken care of in constructor
	   << entry.getID() << "_" 
	   << startAddress << "-" 
	   << endAddress;
	std::string writeFileName = ss.str();
	FILE *writeFile;
	writeFile = fopen(writeFileName.c_str(), "wb");
	unsigned long size = endAddress - startAddress;
	unsigned long bufSize = 1024;
	char buffer[bufSize];

	unsigned long bytesLeft = size;
	unsigned long totalBytesRead = 0;
	unsigned long totalBytesWritten = 0;
	if (lseek64(memFd, startAddress, SEEK_SET) < 0) {
		perror("LSEEK");
		return(1);
	}

	while (bytesLeft > 0) {
		int toRead = std::min(bytesLeft, bufSize);
		if (totalBytesRead = read(memFd, buffer, toRead) < 0) {
			std::cerr << "Error reading mem of map entry id=" 
			 		  << entry.getID() << " ("
			 		  << strerror(errno) << ")" 
					  << std::endl;
			break;
		}
		
		if (totalBytesWritten = fwrite(buffer, sizeof(char), toRead, writeFile) < 0) {
			std::cerr << "Error writing mem of map entry id=" 
			 		  << entry.getID() << " ("
			 		  << strerror(errno) << ")" 
					  << std::endl;
			break;
		}

		bytesLeft -= toRead;
	}
	return totalBytesWritten;
}





MapEntry::MapEntry(int id, const std::string &entry) 
	: id{id}
	, fullEntry{entry} {
	std::smatch smatches;

	std::regex_search(fullEntry, smatches, regexp);
	if (smatches.size() == 8) {
		bool error = false;
		// The parsing below used to be done with std::stol but the Android NDK
		// doesn't understand std::stol. While this can be circumvented by, e.g.,
		// using crystax, I just substituted std::stroul for the time being. Note that
		// this makes the try/catch statements useless and nullified any current validation. 
		// So be it.

		// Parse start address (1)
		try {
			startAddress = std::strtoul(smatches[1].str().c_str(), nullptr, 16);
		} catch (std::invalid_argument &e) {
			std::cerr << "Failure Parsing start address: " << e.what() << std::endl;
			throw parse_exception();
		} catch (std::out_of_range &e) {
			std::cerr << "Failure Parsing start address: " << e.what() << std::endl;
			throw parse_exception();
		}
		
		// Parse end address (2)
		try {
			endAddress = std::strtoul(smatches[2].str().c_str(), nullptr, 16);
		} catch (std::invalid_argument &e) {
			std::cerr << "Failure Parsing start address: " << e.what() << std::endl;
			throw parse_exception();
		} catch (std::out_of_range &e) {
			std::cerr << "Failure Parsing start address: " << e.what() << std::endl;
			throw parse_exception();
		}

		// Parse perms (3)
		perms = smatches[3].str();

		// Parse offset (4)
		try {
			offset = std::strtoul(smatches[4].str().c_str(), nullptr, 16);
		} catch (std::invalid_argument &e) {
			std::cerr << "Failure Parsing start address: " << e.what() << std::endl;
			throw parse_exception();
		} catch (std::out_of_range &e) {
			std::cerr << "Failure Parsing start address: " << e.what() << std::endl;
			throw parse_exception();
		}

		// Parse dev (5) 
		dev = smatches[5].str();

		// Parse inode (6)
		try {
			inode = std::strtoul(smatches[6].str().c_str(), nullptr, 10);
		} catch (std::invalid_argument &e) {
			std::cerr << "Failure Parsing start address: " << e.what() << std::endl;
			throw parse_exception();
		} catch (std::out_of_range &e) {
			std::cerr << "Failure Parsing start address: " << e.what() << std::endl;
			throw parse_exception();
		}

		// Parse path name (7)
		pathName = smatches[7].str();

		// Parse type
		if (pathName.size() == 0) {
			type = MemType::_EMPTY;
		} else if (pathName[0] != '[') {
			type = MemType::_FILE;
		} else if (pathName.compare(0, 5, "[heap") == 0) {
			type = MemType::_HEAP;
		} else if (pathName.compare(0, 6, "[stack") == 0) {
			type = MemType::_STACK;
		} else if (pathName.compare(0, 5, "[vdso") == 0) {
			type = MemType::_VDSO;
		} else if (pathName.compare(0, 9, "[vsyscall") == 0) {
			type = MemType::_VSYSCALL;
		} else if (pathName.compare(0, 4, "anon") == 0) {
			type = MemType::_ANON;
		} else {
			type = MemType::_EMPTY;
		}
	}
}

const std::regex MapEntry::regexp(R"(^([0-9a-z]+)-([0-9a-z]+) (\S+) ([0-9a-z]+) (\S+) ([0-9]+)\s+(\S*.*)$)");

bool MapEntry::isHEAP() {return bool(type == MemType::_HEAP);}
bool MapEntry::isSTACK() {return bool(type == MemType::_STACK);}
bool MapEntry::isVDSO() {return bool(type == MemType::_VDSO);}
bool MapEntry::isVVAR() {return bool(type == MemType::_VVAR);}
bool MapEntry::isVSYSCALL() {return bool(type == MemType::_VSYSCALL);}
bool MapEntry::isFILE() {return bool(type == MemType::_FILE);}
bool MapEntry::isANON() {return bool(type == MemType::_ANON);}
bool MapEntry::isEMPTY() {return bool(type == MemType::_EMPTY);}
int MapEntry::getID() {return id;}
unsigned long MapEntry::getStartAddress() {return startAddress;}
unsigned long MapEntry::getEndAddress() {return endAddress;}

std::string MapEntry::modifiedMapsFormat() {
	std::stringstream ss;
	ss << std::left << std::setw(6) << id
	   << fullEntry;
	return ss.str();
}

MemType MapEntry::memType() {return type;}


MemType MemTypeConvert::stom(const std::string &str) {
	try {
		return stomMap.at(str);
	} catch (std::out_of_range &e) {
		throw parse_exception(e.what());
	}
}

std::string MemTypeConvert::mtos(const MemType type) {
	try {
		return mtosMap.at(type);
	} catch (std::out_of_range &e) {
		throw parse_exception(e.what());
	}
}

const std::map<std::string, MemType> MemTypeConvert::stomMap({
	{"heap", MemType::_HEAP},
	{"stack", MemType::_STACK},
	{"vdso", MemType::_VDSO},
	{"vvar", MemType::_VVAR},
	{"vsyscal", MemType::_VSYSCALL},
	{"file", MemType::_FILE},
	{"anon", MemType::_ANON},
	{"empty", MemType::_EMPTY},
	{"all", MemType::_ALL},
	{"suball", MemType::_SUBALL}
});

const std::map<MemType, std::string> MemTypeConvert::mtosMap({
	{MemType::_HEAP, "heap"},
	{MemType::_STACK, "stack"},
	{MemType::_VDSO, "vdso"},
	{MemType::_VVAR, "vvar"},
	{MemType::_VSYSCALL, "vsyscal"},
	{MemType::_FILE, "file"},
	{MemType::_ANON, "anon"},
	{MemType::_EMPTY, "empty"},
	{MemType::_ALL, "all"},
	{MemType::_SUBALL, "suball"}
});
