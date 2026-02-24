<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<xsl:template match="/doc">
    <html><body>
    <xsl:for-each select="response">
        <h2>File content :</h2>
        <xsl:value-of select="file"/>
        <hr/>
    </xsl:for-each>
    </body></html>
</xsl:template>
</xsl:stylesheet>
