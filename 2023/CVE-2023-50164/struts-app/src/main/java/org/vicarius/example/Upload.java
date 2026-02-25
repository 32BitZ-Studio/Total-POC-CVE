package org.vicarius.example;

import com.opensymphony.xwork2.ActionSupport;
import java.io.File;
import java.util.logging.Logger;

import org.apache.commons.io.FileUtils;

public class Upload extends ActionSupport {

    private static final Logger LOG = Logger.getLogger(Upload.class.getName());

    private File upload;
    private String uploadFileName;
    private String uploadContentType;

    // Custom upload logic
    @Override
    public String execute() {
        LOG.info(() -> "Try to upload '%s' with name '%s' and contentType '%s'.".formatted(upload, uploadFileName,
                uploadContentType));

        if (uploadFileName != null) {
            try {
                // Specify the directory where files will be uploaded
                String uploadDirectory = System.getProperty("catalina.home") + "/uploads/";
                LOG.info("uploadDirectory: " + uploadDirectory);

                // Create the destination file
                File destFile = new File(uploadDirectory, uploadFileName);
                LOG.info("destFile: " + destFile);

                // Copy the uploaded file to the destination
                FileUtils.copyFile(upload, destFile);

                // Add message to reflect the exact upload path on the frontend
                addActionMessage("File uploaded successfully to " + destFile.getAbsolutePath());

                return SUCCESS;
            } catch (Exception e) {
                addActionError(e.getMessage());
                LOG.severe(e.toString());
                return ERROR;
            }
        } else {
            return INPUT;
        }
     }

    // Getters and setters
    public File getUpload() {
        return upload;
    }

    public void setUpload(File upload) {
        this.upload = upload;
    }

    public String getUploadFileName() {
        return uploadFileName;
    }

    public void setUploadFileName(String uploadFileName) {
        this.uploadFileName = uploadFileName;
    }

    public String getUploadContentType() {
        return uploadContentType;
    }

    public void setUploadContentType(String uploadContentType) {
        this.uploadContentType = uploadContentType;
    }

}
