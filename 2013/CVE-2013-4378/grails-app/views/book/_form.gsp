<%@ page import="es.codemotion.grailsxss.Book" %>



<div class="fieldcontain ${hasErrors(bean: bookInstance, field: 'isbn', 'error')} ">
	<label for="isbn">
		<g:message code="book.isbn.label" default="Isbn" />
		
	</label>
	<g:textField name="isbn" value="${bookInstance?.isbn}"/>
</div>

<div class="fieldcontain ${hasErrors(bean: bookInstance, field: 'pubDate', 'error')} required">
	<label for="pubDate">
		<g:message code="book.pubDate.label" default="Pub Date" />
		<span class="required-indicator">*</span>
	</label>
	<g:datePicker name="pubDate" precision="day"  value="${bookInstance?.pubDate}"  />
</div>

<div class="fieldcontain ${hasErrors(bean: bookInstance, field: 'title', 'error')} ">
	<label for="title">
		<g:message code="book.title.label" default="Title" />
		
	</label>
	<g:textField name="title" value="${bookInstance?.title}"/>
</div>

