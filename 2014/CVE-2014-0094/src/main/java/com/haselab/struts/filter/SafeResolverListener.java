package com.haselab.struts.filter;

/*
 *  see
 *  https://gist.github.com/nakamura-to/11347570
 */

 
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
 
import org.apache.commons.beanutils.BeanUtilsBean;
 
public class SafeResolverListener implements ServletContextListener {
    @Override
    public void contextInitialized(ServletContextEvent event) {
      SafeResolver resolver = new SafeResolver();
      BeanUtilsBean.getInstance().getPropertyUtils().setResolver(resolver);
    }
 
    @Override
    public void contextDestroyed(ServletContextEvent event) {
        // nothing
    }
}