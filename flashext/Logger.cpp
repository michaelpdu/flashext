#include "Logger.h"
#include "wdbgexts.h"

namespace md
{

	Logger* Logger::s_instance = NULL;

	Logger::Logger(void)
		: m_uiLevel(LOGLEVEL_INFO)
	{

	}

	Logger::~Logger(void)
	{
	}

	Logger* Logger::getInstance()
	{
		if (!s_instance) {
			s_instance = new Logger();
		}
		return s_instance;
	}

	void Logger::releaseInstance()
	{
		delete s_instance;
		s_instance = NULL;
	}

	void Logger::setLevel(LOGLEVEL level)
	{
		m_uiLevel = level;
	}

	LOGLEVEL Logger::getLevel()
	{
		return m_uiLevel;
	}

	void Logger::output(const std::string& msg, LOGLEVEL level)
	{
		if (level >= m_uiLevel) {
			dprintf(msg.c_str());
		}
	}

}
