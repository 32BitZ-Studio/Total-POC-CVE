# specify the VCL syntax version to use
vcl 4.1;

backend default {
  .host = "backend";
  .port = "8080";
}

sub vcl_recv {
  return (pass);
}