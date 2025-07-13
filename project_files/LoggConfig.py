import logging
import os
 
###############################################################################
##  This class can be used to initialize a Logger. It supports multiple      ##
##  level of logging : INFO and DEBUG. Either 1 or multiple levels can be    ##
##  chosen. It also supports logging to file as well as console. By default  ##
##  logs will be written to a file in specified directory. Optionally,       ##
##  console logging can be enabled. Configuration has to be sent as a JSON   ##
##  Details and key of configuration are given below:                        ##
##                                                                           ##
##  config ={                                                                ##
##            "LOG_PATH":"",                                                 ##
##            "LOG_LEVEL":[],                                                ##
##            "CONSOLE_LOGS_ENABLED":"",                                     ##
##            "SERVICE_NAME":"",                                             ##
##            "SERVICE_ID":""                                                ##
##        }                                                                  ##
##                                                                           ##
##  "LOG_PATH":"", - Directory for log files                                 ##
##  "LOG_LEVEL":[], - Level of Log in list ["INFO"] or ["INFO","DEBUG"] etc  ##
##  "CONSOLE_LOGS_ENABLED":"", - "True" to print console logs "False" to not ##
##  "SERVICE_NAME":"", - Name of the service that logger uses and prints in  ##
##                       each log. Preferrably a unique identifier           ##
##  "SERVICE_ID":"" - ID of the service that logger uses and prints in each  ##
##                    log. Preferrably a unique identifier                   ##
###############################################################################
class LocalLogger():
 
    def __init__(self, config):
 
        self.logFormat = logging.Formatter('%(asctime)s - [%(levelname)s] - %(name)s - %(message)s')
 
        self.logDirPath = config["LOG_PATH"]
        self.loglevel = config["LOG_LEVEL"] #List has to be sent ["INFO"] or ["DEBUG"] or ["INFO", "DEBUG"]
        self.enableConsoleLogs = config["CONSOLE_LOGS_ENABLED"]
        self.serviceName = config["SERVICE_NAME"]
        self.serviceId = config["SERVICE_ID"]
        
        if(None in self.__dict__.values()):
            print("Cannot Initialize logger due to invalid configuration")
            raise Exception("Cannot Initialize logger due to invalid configuration")
        
        if(type(self.loglevel) != list):
            print("Cannot Initialize logger due to invalid configuration")
            raise Exception("Cannot Initialize logger due to invalid configuration")
        
        if(self.enableConsoleLogs.lower().strip() == "true"):
            self.enableConsoleLogs = True
        elif(self.enableConsoleLogs.lower().strip() == "false"):
            self.enableConsoleLogs = False
        else:
            self.enableConsoleLogs = None
        
        try:
            if not os.path.exists(self.logDirPath):
                os.makedirs(self.logDirPath)
                print(f"Directory '{self.logDirPath}' created successfully.")
            if os.access(self.logDirPath, os.W_OK):
                pass
            else:
                print(f"Directory '{self.logDirPath}' is not writable.")
                raise Exception(f"Cannot Initialize logger due to invalid configuration. Directory '{self.logDirPath}' is not writable.")
        
        except Exception as e:
            print(f"An error occurred while checking Log Directory Path: {e}")
            raise Exception(f"An error occurred while checking Log Directory Path: {e}")
 
    def addConsoleLogHandler(self, logger, logLevel):
        # Create a console handler for printing to console
        if(logLevel.lower().strip() == "info"):
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)  # Print INFO and higher messages to console
            console_handler.setFormatter(self.logFormat)
            logger.addHandler(console_handler)
        if(logLevel.lower().strip() == "debug"):
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.DEBUG)  # Print DEBUG and higher logs to console
            console_handler.setFormatter(self.logFormat)
            logger.addHandler(console_handler)
        if(logLevel.lower().strip() == "warning"):
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.WARNING)  # Print WARNING and higher logs to console
            console_handler.setFormatter(self.logFormat)
            logger.addHandler(console_handler)
        if(logLevel.lower().strip() == "error"):
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.ERROR)  # Print ERROR and higher logs to console
            console_handler.setFormatter(self.logFormat)
            logger.addHandler(console_handler)
        return
    
    def addFileLogHandler(self, logger, logLevel, filePath):
        if(logLevel.lower().strip() == "info"):
            info_handler = logging.FileHandler(filePath)
            info_handler.setLevel(logging.INFO)  # Capture INFO and Higher levels
            info_handler.setFormatter(self.logFormat)
            logger.addHandler(info_handler)
        if(logLevel.lower().strip() == "debug"):
            debug_handler = logging.FileHandler(filePath)
            debug_handler.setLevel(logging.DEBUG)  # Capture DEBUG and Higher levels
            debug_handler.setFormatter(self.logFormat)
            logger.addHandler(debug_handler)
        if(logLevel.lower().strip() == "warning"):
            debug_handler = logging.FileHandler(filePath)
            debug_handler.setLevel(logging.WARNING)  # Capture WARNING and Higher levels
            debug_handler.setFormatter(self.logFormat)
            logger.addHandler(debug_handler)
        if(logLevel.lower().strip() == "error"):
            debug_handler = logging.FileHandler(filePath)
            debug_handler.setLevel(logging.ERROR)  # Capture WARNING and Higher levels
            debug_handler.setFormatter(self.logFormat)
            logger.addHandler(debug_handler)
        return
 
    
    def createLocalLogger(self):
        
        self.loglevel = [s.lower().strip() for s in self.loglevel]
        logger = logging.getLogger(name=f"{self.serviceName}_{self.serviceId}")
 
        logger.setLevel(logging.DEBUG if "debug" in self.loglevel else logging.INFO)
 
        if("info" in self.loglevel):
            logPath = os.path.join(self.logDirPath, f"{self.serviceName}_{self.serviceId}_Info.log")
            self.addFileLogHandler(logger, "INFO", logPath)
 
        if("debug" in self.loglevel):
            logPath = os.path.join(self.logDirPath, f"{self.serviceName}_{self.serviceId}_Debug.log")
            self.addFileLogHandler(logger, "DEBUG", logPath)
        
        if("warning" in self.loglevel):
            logPath = os.path.join(self.logDirPath, f"{self.serviceName}_{self.serviceId}_Warning.log")
            self.addFileLogHandler(logger, "WARNING", logPath)
        
        if("error" in self.loglevel):
            logPath = os.path.join(self.logDirPath, f"{self.serviceName}_{self.serviceId}_Error.log")
            self.addFileLogHandler(logger, "ERROR", logPath)
 
        # Add console handler only once based on the highest required log level
        if self.enableConsoleLogs:
            if "debug" in self.loglevel:
                self.addConsoleLogHandler(logger, "DEBUG")
            elif "info" in self.loglevel:
                self.addConsoleLogHandler(logger, "INFO")
            elif "warning" in self.loglevel:
                self.addConsoleLogHandler(logger, "WARNING")
            elif "error" in self.loglevel:
                self.addConsoleLogHandler(logger, "ERROR")
 
        return logger