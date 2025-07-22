#pragma once
namespace paginghook
{
	bool Initialize();
	void Unitialize();
	bool ReplaceMap(PEPROCESS peprocess);
	void RestoreMap(PEPROCESS peprocess);
};

