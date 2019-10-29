package org.wso2.carbon.identity.oauth.endpoint.ciba;

public class CibaAuthFailedException extends Exception {

    private int status;
    private String errorCode;
    private String errorDescription;

    public CibaAuthFailedException(int status, String errorCode, String errorDescription) {

        this.status = status;
        this.errorCode = errorCode;
        this.errorDescription = errorDescription;

    }

    public int getStatus() {

        return status;
    }

    public void setStatus(int status) {

        this.status = status;
    }

    public String getErrorCode() {

        return errorCode;
    }

    public void setErrorCode(String errorCode) {

        this.errorCode = errorCode;
    }

    public String getErrorDescription() {

        return errorDescription;
    }

    public void setErrorDescription(String errorDescription) {

        this.errorDescription = errorDescription;
    }
}
