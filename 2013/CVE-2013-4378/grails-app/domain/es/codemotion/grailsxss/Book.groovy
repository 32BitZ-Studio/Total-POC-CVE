package es.codemotion.grailsxss

class Book {

    String title
    String isbn
    Date pubDate

    static constraints = {
	title nullable: false, blank: false
	isbn nullable: false, blank: false
    }

}
