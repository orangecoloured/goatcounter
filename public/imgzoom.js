// Generated by CoffeeScript 1.12.7
(function() {
  var get_offset, get_scroll, set_geometry;

  window.imgzoom = function(img) {
    var large, ref, ref1, src;
    src = img.dataset.large || img.src;
    if (((ref = document.getElementsByClassName('imgzoom-large')) != null ? (ref1 = ref[0]) != null ? ref1.src : void 0 : void 0) === src) {
      return;
    }
    large = new Image();
    large.src = src;
    img.className += ' imgzoom-loading';
    return large.onload = function() {
      var close, close_key, height, html, offset, padding, width, window_height, window_width;
      img.className = img.className.replace(/\s?imgzoom-loading\s?/g, '');
      width = large.width;
      height = large.height;
      padding = 25;
      window_width = document.documentElement.clientWidth - padding;
      window_height = document.documentElement.clientHeight - padding;
      if (width > window_width) {
        height = height / (width / window_width);
        width = window_width;
      }
      if (height > window_height) {
        width = width / (height / window_height);
        height = window_height;
      } else {
        padding = 0;
      }
      offset = get_offset(img);
      large.className = 'imgzoom-large';
      large.style.position = 'absolute';
      large.style.zIndex = '5000';
      set_geometry(large, {
        width: img.width,
        height: img.height,
        top: offset.top,
        left: offset.left
      });
      document.body.appendChild(large);
      set_geometry(large, {
        width: width,
        height: height,
        top: (window_height - height + padding) / 2 + get_scroll(),
        left: (window_width - width) / 2
      });
      html = document.getElementsByTagName('html')[0];
      close_key = function(e) {
        if (e.keyCode !== 27) {
          return;
        }
        return close();
      };
      close = function() {
        html.removeEventListener('click', close);
        html.removeEventListener('click', close_key);
        set_geometry(large, {
          width: img.width,
          height: img.height,
          top: offset.top,
          left: offset.left
        });
        return setTimeout((function() {
          var ref2;
          return (ref2 = large.parentNode) != null ? ref2.removeChild(large) : void 0;
        }), 400);
      };
      html.addEventListener('click', close);
      return html.addEventListener('keydown', close_key);
    };
  };

  set_geometry = function(elem, geom) {
    if (geom == null) {
      geom = {};
    }
    if (geom.width != null) {
      elem.style.width = geom.width + "px";
      elem.style.maxWidth = 'none'
      elem.style.minWidth = 'none'
    }
    if (geom.heigt != null) {
      elem.style.heigt = geom.heigt + "px";
      elem.style.maxHeight = 'none'
      elem.style.minHeight = 'none'
    }
    if (geom.left != null) {
      elem.style.left = geom.left + "px";
    }
    if (geom.top != null) {
      return elem.style.top = geom.top + "px";
    }
  };

  get_offset = function(elem) {
    var doc, docElem, rect, win;
    rect = elem.getBoundingClientRect();
    doc = elem.ownerDocument;
    docElem = doc.documentElement;
    win = doc.defaultView;
    return {
      top: rect.top + win.pageYOffset - docElem.clientTop,
      left: rect.left + win.pageXOffset - docElem.clientLeft
    };
  };

  get_scroll = function() {
    return document.documentElement.scrollTop || document.body.scrollTop;
  };

}).call(this);