package com.moresec.control;

import com.moresec.service.BookService;
import com.moresec.service.FailingSelfValidation;
import com.moresec.dao.Book;

import java.util.List;

import javax.validation.Valid;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;


@Path("bookService")
@Produces(MediaType.APPLICATION_JSON)
public class BookController {

    BookService bookService = new BookService();

    @Path("/books")
    @GET
    public List<Book> getBooks() {
        List<Book> listOfBooks = bookService.getAllBooks();
        return listOfBooks;
    }


    @Path("/book/{id}")
    @GET
    public Book getBookById(@PathParam(value = "id") int id) {
        return bookService.getBook(id);
    }

    @Consumes(MediaType.APPLICATION_JSON)
    @Path("/books")
    @POST
    public Book addBook(@Valid Book Book) {
        return bookService.addBook(Book);
    }

    @Path("/books")
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    public Book updateBook(@Valid Book Book) {
        return bookService.updateBook(Book);

    }

    @Produces(MediaType.APPLICATION_JSON)
    @Path("/book/{id}")
    @DELETE
    public void deleteBook(@PathParam(value = "id")int id) {
        bookService.deleteBook(id);

    }

    @GET
    @Path("selfValidatingBeanParam")
    public FailingSelfValidation selfValidating(@Valid @BeanParam FailingSelfValidation beanParameter) {
        return beanParameter;
    }

    @POST
    @Path("selfValidatingPayload")
    public FailingSelfValidation selfValidatingPayload(@Valid FailingSelfValidation payload) {
        return payload;
    }

}