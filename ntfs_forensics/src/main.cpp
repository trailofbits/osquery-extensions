/*
 * Copyright (c) 2018 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



#include <iostream>

#include "ntfs_forensics.h"
#include "extension.h"

int runAsStandalone(int argc,  char * argv[]) {
	int rval = -1;
	FileInfo info;
	std::string device("\\\\.\\PhysicalDrive0");
	int partition = 2; // DEBUG, testing purposes only
	Device *d = NULL;
	Partition *p = NULL;
	try {
		d = new Device(device);
		p = new Partition(*d, partition);
	}
	catch (const std::runtime_error &err) {
		std::cerr << "exception thrown on opening file system: " << err.what() << "\n";
		delete p;
		delete d;
		return 1;
	}
	if (0 == std::strcmp(argv[argc], "--path")) {
		rval = p->getFileInfo(std::string(argv[argc + 1]), info);
	}
	else if (0 == std::strcmp("--inode", argv[argc])) {
		std::stringstream inode_str;
		inode_str << argv[argc + 1];
		uint64_t inode;
		inode_str >> inode;
		rval = p->getFileInfo(inode, info);
	}
	else {
		std::cerr << "unrecognized argument " << argv[argc] << "\n"
			<< "valid values are :\n"
			<< "\t--path <path>\n"
			<< "\t--inode <inode>\n";
		delete p;
		delete d;
		return 1;
	}
	std::cout << "rval from getFileInfo(inode) is " << rval << std::endl;
	if (rval != 0) { return 0; }
	std::cout << "collected info:\n" << info.getStringRep();
	delete p;
	delete d;
	return rval;
}

int runAsExtension(int argc, char* argv[]) {
	std::cout << "Connecting to the running osquery instance..." << std::endl;

	osquery::Initializer runner(argc, argv, osquery::ToolType::EXTENSION);

	auto status = osquery::startExtension("ntfs", "1.0.0");
	if (!status.ok()) {
		LOG(ERROR) << status.getMessage();
		runner.requestShutdown(status.getCode());
	}

	runner.waitForShutdown();

	return 0;
}

void showUsage( char* argv[]) {
	const char* usage =
		" [--standalone [--path <path> | --inode <inode>] ]\n"
		"\n"
		"\t--standalone --path <path>  Print info about <path>.\n"
		"\t--standalone --inode <inode>  Print info about <inode>.\n"
		"\t						If not specified, it will run as an osquery extension\n";

	std::cerr << "Usage: " << argv[0] << usage;
}

int main(int argc,  char* argv[]) {
	if (argc > 1 && std::strcmp("--standalone", argv[1]) == 0) {
		if (argc > 3) {
			return runAsStandalone(2, argv);
		}
		else {
			showUsage(argv);
			return 0;
		}
	}
	else if (argc == 2 && std::strcmp(argv[1], "--help") == 0) {
		showUsage(argv);
		return 0;
	}
	else {
		return runAsExtension(argc, argv);
	}
}
