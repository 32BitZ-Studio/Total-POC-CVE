# Vulnerable snippet
Integer overflow that 
```
 if (!msg->text_len ||
     nf_len >= NCRX_LINE_MAX || 
     nf_off > nf_len ||          # the line that was missing
     nf_off + msg->text_len > nf_len)
     goto einval;
```


## Impact
heap overflow in `copy_msg(struct ncrx_msg *src)`.

```
dst = malloc(sizeof(*dsg) + src->text_len + 1);
...
if (src->ncfrag_len) {
  memset(dst->text, 0, src->text_len + 1);
  memcpy(dst->text + src->ncfrag_off, src->text, src->ncfrag_len);
  ..
}
```
Note that `ncrx_msg->ncfrag_off` is a signed integer, so the `dst->text + src->ncfrag_off` is a signed addition.


## Constraints in building an exploit
Assuming attackers can control the entire message, then they get to corrupt the heap metadata

- Interest of data:
  - `text`: the message body, where its length plays a crucial role 
  - `pf_off`: the netconsle frag offset we are going to start writing from, 
  - `pf_len`: the total netconsole frag length, it should be no larger than NCRX_LINE_MAX, which is 8192

Here we provide an example of corrupted data
```
# setting pf_len to some normal value
pf_len = 1024

# setting pf_off to an negative 
pf_off = (1 << 32) - 0xff 
text = b'a' * 512

# use the integer overflow vulnerability to bypass the check
# now, -256(pf_off) + 512(text.length) < 1024()
# in `copy_msg`'s  memcpy, it will corrupt the text->dst's heap metadata
# i.e. memcpy(text->dst - 0xff, ...);
```
