<?xml version='1.0'?>
<xsl:stylesheet
     xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
     xmlns:fo="http://www.w3.org/1999/XSL/Format"
     xmlns:d="http://docbook.org/ns/docbook"
     exclude-result-prefixes="d"
     version="1.0">
<xsl:import href="/usr/share/sgml/docbook/xsl-ns-stylesheets/html/docbook.xsl"/>

<xsl:param name="html.stylesheet" select="'http://docs.initware.com/reference/style.css'"/>

<xsl:template match="d:citerefentry[not(@project)]">
  <a>
    <xsl:attribute name="href">
      <xsl:value-of select="d:refentrytitle"/>
      <xsl:text>.</xsl:text>
      <xsl:value-of select="d:manvolnum"/>
      <xsl:text>.html#</xsl:text>
      <xsl:value-of select="d:refentrytitle/@target"/>
    </xsl:attribute>
    <xsl:call-template name="inline.charseq"/>
  </a>
</xsl:template>

<xsl:template name="genviewport">
  <xsl:element name="meta">
  <xsl:attribute name="name">viewport</xsl:attribute>
  <xsl:attribute name="content">width=device-width, initial-scale=1.0</xsl:attribute>
  </xsl:element>
</xsl:template>

<xsl:template name="user.head.content">
  <xsl:call-template name="genviewport" />
</xsl:template>

<xsl:template name="user.header.content">
  <div id="Masthead">
    <a href="index.html" id="MastheadLogo"></a>
      <div id="MastheadText">
        InitWare Manual Pages
     </div>
    </div>
    <hr id="MastheadHR" />
  <a>
    <xsl:attribute name="href">
    <xsl:text>index.html</xsl:text>
    </xsl:attribute>
    <xsl:text>Index </xsl:text>
  </a>·
  <span style="float:right">
    <xsl:value-of select="/d:refentry/d:refmeta/d:refmiscinfo[@class='source']"/>
  </span>
</xsl:template>

<xsl:template match="literal">
  <xsl:text>"</xsl:text>
  <xsl:call-template name="inline.monoseq"/>
  <xsl:text>"</xsl:text>
</xsl:template>

<xsl:output method="html" encoding="UTF-8" indent="no"/>

</xsl:stylesheet>
