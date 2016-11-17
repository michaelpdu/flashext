#include "Logger.h"
#include "wdbgexts.h"
#include <iomanip>
#include <ctime>

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
            std::string levelFlag;
            switch (level)
            {
            case LOGLEVEL_ERROR:
                levelFlag = "[ERROR] ";
                break;
            case LOGLEVEL_WARN:
                levelFlag = "[WARN] ";
                break;
            case LOGLEVEL_INFO:
                levelFlag = "[INFO] ";
                break;
            case LOGLEVEL_MSG:
                levelFlag = "[MSG] ";
                break;
            case LOGLEVEL_DEBUG:
                levelFlag = "[DEBUG] ";
                break;
            case LOGLEVEL_TRACE:
                levelFlag = "[TRACE] ";
                break;
            }

            std::stringstream ss;
            auto t = std::time(nullptr);
            auto tm = *std::localtime(&t);
            ss << "[" << std::put_time(&tm, "%d/%m/%Y %H-%M-%S") << "]" << levelFlag << msg << std::endl;
			dprintf(ss.str().c_str());
		}
	}

}
