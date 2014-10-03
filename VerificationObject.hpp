class VerificationObject {
public:
	void connectWith(TrustedObject trustedObject);
	void connectWith(UntrustedObject untrustedObject);
	void verifyEntry(Log log);
	void verifyAll();
}
