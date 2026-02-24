package com.ambersail.struts2.action;

import com.opensymphony.xwork2.ActionSupport;
import java.io.File;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.struts2.convention.annotation.Result;
import org.apache.struts2.convention.annotation.Results;
import org.apache.struts2.rest.DefaultHttpHeaders;
import org.apache.struts2.rest.HttpHeaders;

/**
 * Action for fileupload to demonstrate CVE-2017-5638 - RCE multipart form
 */
@Results({ @Result(name = "success", type = "redirectAction", params = { "actionName", "fileupload" }) })
public class FileuploadController extends ActionSupport {

    final static Logger logger = LogManager.getLogger("FileUploadController");

    private File fileUpload;
    private String fileUploadContentType;
    private String fileUploadFileName;

    public String getFileUploadContentType() {
        return fileUploadContentType;
    }

    public void setFileUploadContentType(String fileUploadContentType) {
        this.fileUploadContentType = fileUploadContentType;
    }

    public String getFileUploadFileName() {
        return fileUploadFileName;
    }

    public void setFileUploadFileName(String fileUploadFileName) {
        this.fileUploadFileName = fileUploadFileName;
    }

    public File getFileUpload() {
        return fileUpload;
    }

    public void setFileUpload(File fileUpload) {
        this.fileUpload = fileUpload;
    }

    public String execute() throws Exception {
        return SUCCESS;

    }

    public HttpHeaders index() {
        return new DefaultHttpHeaders("index").disableCaching();
    }

    public String create() throws Exception {

        return "result";
    }

}