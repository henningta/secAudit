class UntrustedObject {
private:
	Log _log;
public:
	void generateInitMessage();
	void verifyInitResponse();
	void createLogEntry();
	void closeLog();
}
