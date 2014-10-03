class UntrustedObject {
private:
	Log log;
public:
	void generateInitMessage();
	void verifyInitResponse();
	void createLogEntry();
	void closeLog();
}
