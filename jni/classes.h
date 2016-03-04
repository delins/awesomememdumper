 #include <memory>
#include <vector>
#include <string>
#include <regex>
#include <map>
#include <exception>

enum MemType {_HEAP, _STACK, _VDSO, _VVAR, _VSYSCALL, _FILE, _ANON, _EMPTY, _ALL, _SUBALL};

class MemTypeConvert {
private:
	static const std::map<std::string, MemType> stomMap;
	static const std::map<MemType, std::string> mtosMap;
public:
	static MemType stom(const std::string &str);
	static std::string mtos(const MemType memType);
};

class parse_exception : public std::exception {
private:
	std::string errorMsg;
public:
	parse_exception() : errorMsg("Parse exception") {};
	parse_exception(const std::string &str) : errorMsg("Parse exception: "+str) {}
	virtual const char* what() const throw() {
		return errorMsg.c_str();
	}
};


class MapEntry {
private:
	int id;
	std::string fullEntry;

	unsigned long startAddress;
	unsigned long endAddress;
	std::string perms;
	unsigned long offset;
	std::string dev;
	unsigned long inode;
	std::string pathName;

	MemType type;

	static const std::regex regexp;
public:
	MapEntry(int id, const std::string &entry);
	bool isHEAP();
	bool isSTACK();
	bool isVDSO();
	bool isVVAR();
	bool isVSYSCALL();
	bool isFILE();
	bool isANON();
	bool isEMPTY();

	int getID();
	unsigned long getStartAddress();
	unsigned long getEndAddress();

	MemType memType();
	std::string modifiedMapsFormat();
};



class MemReader {
private:
	int pid;
	std::string memFile;
	std::string outputDir;
	std::vector<std::string> maps;
	unsigned long readMemSingle(MapEntry &entry, int memFd);
public:
	//MemReader() = default;
	//MemReader(const MemReader &) = default;
	MemReader(int pid, const std::string &outputDir);
	unsigned long readMem(std::vector<std::shared_ptr<MapEntry>> &entries);
};





class MapsParser {
private:
	int pid;
	std::string maps_file;
	std::map<MemType, std::vector<std::shared_ptr<MapEntry>>> memMap;
	std::vector<std::string> mapEntryStrings;
public:
	MapsParser() = default;
	MapsParser(int pid);
	int parse();
	std::vector<std::shared_ptr<MapEntry>> retrieveMapEntries(MemType type);
	void dumpModifiedMapsFile(const std::string &dir);
};