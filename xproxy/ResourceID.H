#ifndef RESOURCEID_H_
#define RESOURCEID_H_
#include <map>
#include "util.H"
#include <iostream>
using namespace std;

class ResourceID
{
public:
	ResourceID();
	virtual ~ResourceID();
	void initOld (unsigned int, unsigned int);
	void initNew (unsigned int, unsigned int);
	unsigned int mapToNew (unsigned int old);
	unsigned int mapToNewSpecial (unsigned int old);
	unsigned int mapToNewNonWindow (unsigned int old);
	unsigned int mapToOld (unsigned int);
	void setRootWindow (unsigned int, unsigned int);
	void addSpecialMap (unsigned int old, unsigned int newID);
	unsigned int getSpecialMap (unsigned int old);
	void addAtomMap (unsigned int old, unsigned int newID);
	unsigned int atomMapToNew (unsigned int old);
	unsigned int atomMapToOld (unsigned int newID);
	bool checkRangeOld(unsigned int id);
	bool checkRangeNew(unsigned int id);
	unsigned int getNewRootWindow () {
		return newRootWindow;
	}
	unsigned int getOldRootWindow () {
			return oldRootWindow;
		}
private:
	unsigned int newBase;
	unsigned int oldBase;
	unsigned int oldMax;
	unsigned int newMax;
	unsigned int newMask;
	unsigned int oldMask;
	unsigned int oldRootWindow;
	unsigned int newRootWindow;
	
	map<unsigned int, unsigned int> specialMap;
	map<unsigned int, unsigned int> atomOldToNewMap;
	map<unsigned int, unsigned int> atomNewToOldMap;
};

#endif /*RESOURCEID_H_*/
