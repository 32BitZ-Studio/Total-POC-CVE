package com.ambersail.struts2.action;

import com.opensymphony.xwork2.ActionSupport;
import com.opensymphony.xwork2.Preparable;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;

public class IndexAction extends ActionSupport implements Preparable {

    final static Logger logger = LogManager.getLogger("IndexAction");

    @Override
    public void prepare() throws Exception {
        logger.debug("prepare");
    }
    public String list() {

        logger.debug("list");
        return SUCCESS;
    }
}