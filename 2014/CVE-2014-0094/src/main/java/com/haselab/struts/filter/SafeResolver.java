package com.haselab.struts.filter;


/* see
   http://aoking.hatenablog.jp/
   https://gist.github.com/nakamura-to/11347570
*/

import org.apache.commons.beanutils.expression.DefaultResolver;

public class SafeResolver extends DefaultResolver {
    @Override
    public String next(String expression) {
       String next = super.next(expression);
       if ("classLoader".equalsIgnoreCase(next)) {
          return "";
       }
       return next;
    }
}
