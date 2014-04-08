#include "ResourceID.H"
ResourceID::ResourceID() {
}

ResourceID::~ResourceID() {
}

void ResourceID::initOld(unsigned int base, unsigned int mask) {
	oldBase = base;
	oldMask = mask;
	oldMax = base | mask;
	if (PRINT_DEBUG)
		cout << " init old resource id, base:"<<base<<", mask"<<mask
				<<", base + mask:"<<base + mask << ", base | mask :"<<(base
				|mask) <<endl;
}

void ResourceID::initNew(unsigned int base, unsigned int mask) {
	newBase = base;
	newMask = mask;
	newMax = base | mask;
	if (PRINT_DEBUG)
		cout << " init new resource id, base:"<<base<<", mask"<<mask<<endl;
}

bool ResourceID::checkRangeOld(unsigned int id) {
	// should we consider root window as a special case?????????
	/*if (id == oldRootWindow)
		return true;*/
	if (id >= oldBase && id <= oldMax)
		return true;
	else
		return false;
}

bool ResourceID::checkRangeNew(unsigned int id) {
	// should we consider root window as a special case?????????
/*	if (id == newRootWindow)
		return true;
*/	
	if (id >= newBase && id <= newMax)
		return true;
	else
		return false;
}

unsigned int ResourceID::mapToNew(unsigned int old) {
	if (!old) return old;
	if (PRINT_DEBUG) {
		if (old != oldRootWindow)
			cout <<" id mapped from old:"<<old<<" to new:"<<old-oldBase+newBase
					<<endl;
		else
			cout <<" id is root window"<<endl;
	}
	if (old == oldRootWindow)
		return newRootWindow;
	if (old >= oldBase && old <= oldMax)
		return old - oldBase + newBase;
	else {
		if (PRINT_DEBUG)
			cout << "not actually mapped. error"<<endl;
		return old;
	}
}

unsigned int ResourceID::mapToNewSpecial(unsigned int old) {
	if (!old) return old;
	if (PRINT_DEBUG) {
		if (old != oldRootWindow)
			cout <<" id mapped from old:"<<old<<" to new:"<<old-oldBase+newBase
					<<endl;
		else
			cout <<" id is root window"<<endl;
	}
	if (old == oldRootWindow)
		return newRootWindow;
	if (old >= oldBase && old <= oldMax)
		return old - oldBase + newBase;
	else {
		if (specialMap.count(old)) {
			if (PRINT_DEBUG) cout << "mapped to special id from "<<old<<" to "<<specialMap[old]
					<<endl;
			return specialMap[old];
		}
		if (PRINT_DEBUG)
			cout << "not actually mapped. error"<<endl;
		return old;
	}
}

unsigned int ResourceID::mapToNewNonWindow(unsigned int old) {
	if (!old) return old;
	if (PRINT_DEBUG) {
		if (old != oldRootWindow)
			cout <<" id mapped from old:"<<old<<" to new:"<<old-oldBase+newBase
					<<endl;
		else
			cout <<" id is root window"<<endl;
	}
	if (old == oldRootWindow)
		return newRootWindow;
	if (old >= oldBase && old <= oldMax)
		return old - oldBase + newBase;
	else {
		if (PRINT_DEBUG)
			cout << "not actually mapped for this non-window resource id."<<endl;
		return old;
	}
}

unsigned int ResourceID::mapToOld(unsigned int newID) {
	if (!newID) return newID;
	if (PRINT_DEBUG) {
		if (newID != newRootWindow)
			cout <<" id mapped from new:"<<newID<<" to old:"<<newID - newBase
					+ oldBase<<endl;
		else
			cout <<" id is root window"<<endl;
	}
	if (newID == newRootWindow)
		return oldRootWindow;
	if (newID >= newBase && newID <= newMax)
		return newID - newBase + oldBase;
	else {
		if (PRINT_DEBUG)
			cout << "not actually mapped."<<endl;
		return newID;
	}
}

void ResourceID::setRootWindow(unsigned int old, unsigned int newroot) {
	oldRootWindow = old;
	newRootWindow = newroot;
	if (PRINT_DEBUG)
		cout <<" root window id, old:"<<old<<", new:"<<newroot<<endl;
}

void ResourceID::addSpecialMap(unsigned int old, unsigned int newID) {
	if (PRINT_DEBUG) cout <<"add a special mapped id from "<<old<<" to "<<newID<<endl;
	specialMap[old] = newID;
}

unsigned int ResourceID::getSpecialMap(unsigned int old) {
	if (specialMap.count(old))
		return specialMap[old];
	else
		return old;
}

void ResourceID::addAtomMap(unsigned int old, unsigned int newID) {
	if (PRINT_DEBUG)
		cout << "Add Atom map from old:"<<old<< " to new:"<<newID<<endl;
	if (old <=68)
		return;
	atomOldToNewMap[old] = newID;
	atomNewToOldMap[newID] = old;
}

unsigned int ResourceID::atomMapToNew(unsigned int old) {
	if (old <=68)
		return old;
	if (!atomOldToNewMap.count(old))
		return old;
	if (PRINT_DEBUG)
		cout << "atom map from old:"<<old<< " to new:"<<atomOldToNewMap[old]
				<<endl;
	return atomOldToNewMap[old];
}

unsigned int ResourceID::atomMapToOld(unsigned int newID) {
	if (newID <=68)
		return newID;
	if (!atomNewToOldMap.count(newID))
		return newID;
	if (PRINT_DEBUG)
		cout << "atom map from new:"<<newID<< " to old:"
				<<atomNewToOldMap[newID]<<endl;
	return atomNewToOldMap[newID];
}

