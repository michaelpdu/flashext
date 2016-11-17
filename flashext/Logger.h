#pragma once

#include <basetsd.h>
#include <string>
#include <sstream>
#include <windows.h>


enum LOGLEVEL{
	LOGLEVEL_OFF    = 6,
	LOGLEVEL_ERROR  = 5,
	LOGLEVEL_WARN   = 4,
	LOGLEVEL_INFO   = 3,
    LOGLEVEL_MSG    = 2,
	LOGLEVEL_DEBUG  = 1,
	LOGLEVEL_TRACE  = 0,
	LOGLEVEL_ALL    = LOGLEVEL_TRACE,
};

namespace md
{

	class Logger
	{
	public:
		static Logger* getInstance();
		static void releaseInstance();

		~Logger(void);

		void setLevel(LOGLEVEL level);
		LOGLEVEL getLevel();

		void output(const std::string& msg, LOGLEVEL level);

	private:
		Logger();
		static Logger* s_instance;

	private:
		LOGLEVEL m_uiLevel;

		
	};

	
}

#define LOG_MACRO(msg, logLevel) {								\
	std::stringstream logBuf;									\
	logBuf << msg;												\
	md::Logger::getInstance()->output(logBuf.str(), logLevel);	\
}

#define LOG_TRACE(msg)	LOG_MACRO(msg, LOGLEVEL_TRACE)
#define LOG_DEBUG(msg)	LOG_MACRO(msg, LOGLEVEL_DEBUG)
#define LOG_MSG(msg)	LOG_MACRO(msg, LOGLEVEL_MSG)
#define LOG_INFO(msg)	LOG_MACRO(msg, LOGLEVEL_INFO)
#define LOG_WARN(msg)	LOG_MACRO(msg, LOGLEVEL_WARN)
#define LOG_ERROR(msg)	LOG_MACRO(msg, LOGLEVEL_ERROR)
