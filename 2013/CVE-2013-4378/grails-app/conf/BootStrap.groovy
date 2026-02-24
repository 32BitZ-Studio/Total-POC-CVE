import es.codemotion.grailsxss.*

class BootStrap {

    def init = { servletContext ->
	def userRole = new Role(authority: 'ROLE_USER').save(flush: true)
	def testUser = new User(username: 'me', enabled: true, password: 'password') 
	testUser.save(flush: true)

	UserRole.create testUser, userRole, true
    }
    def destroy = {
    }
}
