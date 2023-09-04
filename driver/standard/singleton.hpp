#pragma once

template <class _Ty>
class  Singleton
{
protected:
	Singleton() {}
public:
	virtual ~Singleton() {}

	template<typename ...Args> static	_Ty* get_instance(Args&& ...args)
	{
		static _Ty instance(std::forward(args)...);
		return &instance;
	}
};