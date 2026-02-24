package com.ambersail.struts2.action;

import com.ambersail.model.Shape;
import com.opensymphony.xwork2.ModelDriven;
import java.util.ArrayList;
import java.util.Collection;
import org.apache.struts2.convention.annotation.Result;
import org.apache.struts2.convention.annotation.Results;
import org.apache.struts2.rest.DefaultHttpHeaders;
import org.apache.struts2.rest.HttpHeaders;

@Results({
    @Result(name="success", type="redirectAction", params = {"actionName" , "shapes"})
})
/* Placeholder controller using struts convention & REST plugins to define endpoints.
A real application would have a much more complete implementation.
*/
public class ShapesController implements ModelDriven<Shape> {

    private Shape model;
    private Collection<Shape> list;

    // Handles /shapes/{id} GET requests
    public HttpHeaders show() {       

        this.model = new Shape();
        this.model.colour = "red";
        this.model.type = "circle";
        this.model.description = "round";

        return new DefaultHttpHeaders("show");
    }

    public HttpHeaders create() {           
        return new DefaultHttpHeaders("success")
            .setLocationId(1);
    }


    // GET /shapes
    public HttpHeaders index() {
  
        list = new ArrayList<Shape>();
        list.add(this.model);

        return new DefaultHttpHeaders("index")
            .disableCaching();
    }

    // Handles /shapes/{id} PUT requests
    public String update() {        
        return "update";
    }

	public Shape getModel() {
		return this.model;
	}
}