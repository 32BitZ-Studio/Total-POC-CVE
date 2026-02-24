package com.moresec.dao;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.dropwizard.validation.ValidationMethod;
import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.constraints.Max;
import javax.validation.constraints.Min;

public class Book {
    int id;
    @NotEmpty
    String title;
    @Min(10)
    @Max(1000)
    long pages;

    public Book() {
    }

    public Book(int id, String title, long pages) {
        super();
        this.id = id;
        this.title = title;
        this.pages = pages;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public long getPages() {
        return pages;
    }

    public void setPages(long pages) {
        this.pages = pages;
    }

    @ValidationMethod(message = "title must not be dummy")
    @JsonIgnore
    public boolean isNotDummy() {
        return !"Dummy".equalsIgnoreCase(title);
    }
}
